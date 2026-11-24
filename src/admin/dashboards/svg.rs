//! Server-drawn SVG for time charts: bars, or one step area when a bucket is too narrow for a bar,
//! and lines. Marks carry titles; colours come from classes in the stylesheet, never from styles.

use maud::{Markup, html};

use super::query::Bucket;

const WIDTH: f64 = 560.0;
const HEIGHT: f64 = 220.0;
const LEFT: f64 = 48.0;
const RIGHT: f64 = 12.0;
const TOP: f64 = 12.0;
const BOTTOM: f64 = 40.0;
const PLOT_WIDTH: f64 = WIDTH - LEFT - RIGHT;
const PLOT_HEIGHT: f64 = HEIGHT - TOP - BOTTOM;
const BASELINE: f64 = HEIGHT - BOTTOM;
/// A bucket narrower than this at the nominal width is drawn as a step area instead of bars.
const MIN_SLOT: f64 = 5.0;
const MAX_GRIDLINES: i64 = 4;
/// The most tick labels a chart writes along its axis.
const MAX_TICKS: usize = 8;

/// The gridline step and the top of the value scale: the smallest 1, 2 or 5 times a power of ten
/// that leaves at most four gridlines, so the scale starts at zero and ends on a whole gridline.
pub fn nice_scale(max: i64) -> (i64, i64) {
    if max <= 0 {
        return (1, 1);
    }
    let mut magnitude: i128 = 1;
    loop {
        for multiple in [1, 2, 5] {
            let step = magnitude * multiple;
            let lines = (i128::from(max) + step - 1) / step;
            if lines <= i128::from(MAX_GRIDLINES) {
                let top = lines * step;
                return (
                    i64::try_from(step).unwrap_or(i64::MAX),
                    i64::try_from(top).unwrap_or(i64::MAX),
                );
            }
        }
        magnitude *= 10;
    }
}

/// The width of a ranked bar as a percentage of the largest value, to one decimal place.
pub fn percent_width(value: i64, max: i64) -> String {
    if max <= 0 {
        return "0.0%".to_owned();
    }
    let share = value.clamp(0, max) as f64 * 100.0 / max as f64;
    format!("{share:.1}%")
}

/// The contiguous runs of buckets that have a value, each as (index, value) pairs.
fn runs(buckets: &[Bucket]) -> Vec<Vec<(usize, i64)>> {
    let mut runs: Vec<Vec<(usize, i64)>> = Vec::new();
    let mut current: Vec<(usize, i64)> = Vec::new();
    for (index, bucket) in buckets.iter().enumerate() {
        match bucket.value {
            Some(value) => current.push((index, value)),
            None if !current.is_empty() => runs.push(std::mem::take(&mut current)),
            None => {}
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    runs
}

/// The geometry of one chart: its scale and the number of buckets across the plot.
struct Plot {
    top: i64,
    step: i64,
    count: usize,
}

impl Plot {
    fn new(buckets: &[Bucket]) -> Plot {
        let max = buckets
            .iter()
            .filter_map(|bucket| bucket.value)
            .max()
            .unwrap_or(0);
        let (step, top) = nice_scale(max);
        Plot {
            top,
            step,
            count: buckets.len(),
        }
    }

    fn slot(&self) -> f64 {
        PLOT_WIDTH / self.count as f64
    }

    /// The left edge of a bucket's slot.
    fn left(&self, index: usize) -> f64 {
        LEFT + self.slot() * index as f64
    }

    fn centre(&self, index: usize) -> f64 {
        self.left(index) + self.slot() / 2.0
    }

    fn y(&self, value: i64) -> f64 {
        BASELINE - PLOT_HEIGHT * value as f64 / self.top as f64
    }

    fn gridlines(&self) -> Vec<i64> {
        (1..=self.top / self.step)
            .map(|line| line * self.step)
            .collect()
    }
}

fn coordinate(value: f64) -> String {
    format!("{value:.2}")
}

/// The time chart as bars: a bar per bucket with a value, or a step area when the buckets are narrow.
pub fn bars(title: &str, buckets: &[Bucket]) -> Markup {
    let plot = Plot::new(buckets);
    let body = if plot.slot() >= MIN_SLOT {
        bar_marks(&plot, buckets)
    } else {
        step_marks(&plot, buckets)
    };
    frame(title, &plot, buckets, body)
}

/// The time chart as a line, broken where a bucket has no value.
pub fn line(title: &str, buckets: &[Bucket]) -> Markup {
    let plot = Plot::new(buckets);
    let body = html! {
        @for run in runs(buckets) {
            polyline.chart-line points=(points(run.iter().map(|(index, value)| (plot.centre(*index), plot.y(*value))))) {}
        }
        @for (index, bucket) in buckets.iter().enumerate() {
            @if let Some(value) = bucket.value {
                circle.chart-point cx=(coordinate(plot.centre(index))) cy=(coordinate(plot.y(value))) r="3" {
                    title { (mark_title(bucket, value)) }
                }
            }
        }
    };
    frame(title, &plot, buckets, body)
}

/// The title of a mark: its date and its exact value.
fn mark_title(bucket: &Bucket, value: i64) -> String {
    format!("{}: {}", bucket.label, super::figure::thousands(value))
}

fn points(points: impl Iterator<Item = (f64, f64)>) -> String {
    points
        .map(|(x, y)| format!("{},{}", coordinate(x), coordinate(y)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn bar_marks(plot: &Plot, buckets: &[Bucket]) -> Markup {
    let width = plot.slot() * 0.7;
    html! {
        @for (index, bucket) in buckets.iter().enumerate() {
            @if let Some(value) = bucket.value {
                rect.chart-bar x=(coordinate(plot.centre(index) - width / 2.0)) y=(coordinate(plot.y(value)))
                    width=(coordinate(width)) height=(coordinate(BASELINE - plot.y(value))) {
                    title { (mark_title(bucket, value)) }
                }
            }
        }
    }
}

/// One step area per run of values, with a transparent mark over each bucket for its title.
fn step_marks(plot: &Plot, buckets: &[Bucket]) -> Markup {
    html! {
        @for run in runs(buckets) {
            polygon.chart-step points=(step_points(plot, &run)) {}
        }
        @for (index, bucket) in buckets.iter().enumerate() {
            @if let Some(value) = bucket.value {
                rect.chart-hit x=(coordinate(plot.left(index))) y=(coordinate(TOP))
                    width=(coordinate(plot.slot())) height=(coordinate(PLOT_HEIGHT)) {
                    title { (mark_title(bucket, value)) }
                }
            }
        }
    }
}

/// The outline of a step area: along the baseline, up to each bucket's value across its slot, and back.
fn step_points(plot: &Plot, run: &[(usize, i64)]) -> String {
    let (first, _) = run[0];
    let (last, _) = run[run.len() - 1];
    let mut outline = vec![(plot.left(first), BASELINE)];
    for (index, value) in run {
        outline.push((plot.left(*index), plot.y(*value)));
        outline.push((plot.left(*index) + plot.slot(), plot.y(*value)));
    }
    outline.push((plot.left(last) + plot.slot(), BASELINE));
    points(outline.into_iter())
}

/// The svg element: its title, the gridlines and their values, the baseline, the x tick labels and the marks.
fn frame(title: &str, plot: &Plot, buckets: &[Bucket], body: Markup) -> Markup {
    html! {
        svg.chart-svg viewBox=(format!("0 0 {WIDTH} {HEIGHT}")) width="100%" role="img" {
            title { (title) }
            g.chart-grid {
                @for value in plot.gridlines() {
                    line x1=(coordinate(LEFT)) y1=(coordinate(plot.y(value))) x2=(coordinate(WIDTH - RIGHT)) y2=(coordinate(plot.y(value))) {}
                }
            }
            line.chart-axis x1=(coordinate(LEFT)) y1=(coordinate(BASELINE)) x2=(coordinate(WIDTH - RIGHT)) y2=(coordinate(BASELINE)) {}
            g {
                @for value in std::iter::once(0).chain(plot.gridlines()) {
                    text.chart-tick x=(coordinate(LEFT - 6.0)) y=(coordinate(plot.y(value) + 4.0)) text-anchor="end" {
                        (super::figure::thousands(value))
                    }
                }
            }
            g {
                @for (index, bucket) in tick_buckets(buckets) {
                    text.chart-tick x=(coordinate(plot.centre(index))) y=(coordinate(BASELINE + 16.0)) text-anchor="middle" {
                        (tick_label(bucket))
                    }
                }
            }
            (body)
        }
    }
}

/// The buckets that get an x tick label: every nth, so that at most eight labels are written.
fn tick_buckets(buckets: &[Bucket]) -> Vec<(usize, &Bucket)> {
    let every = buckets.len().div_ceil(MAX_TICKS).max(1);
    buckets
        .iter()
        .enumerate()
        .filter(|(index, _)| index % every == 0)
        .collect()
}

/// A tick label: the clock of an hourly bucket, or the month and day of a daily one.
fn tick_label(bucket: &Bucket) -> &str {
    if let Some((_, clock)) = bucket.label.rsplit_once(' ') {
        clock
    } else {
        bucket.label.get(5..).unwrap_or(bucket.label.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(label: &str, value: Option<i64>) -> Bucket {
        Bucket {
            label: label.to_owned(),
            value,
        }
    }

    #[test]
    fn the_scale_steps_by_one_two_or_five_with_at_most_four_gridlines() {
        assert_eq!(
            nice_scale(0),
            (1, 1),
            "nothing to scale: one gridline at one"
        );
        assert_eq!(nice_scale(4), (1, 4));
        assert_eq!(
            nice_scale(5),
            (2, 6),
            "a step of one would need five gridlines"
        );
        assert_eq!(nice_scale(7), (2, 8));
        assert_eq!(nice_scale(1_000), (500, 1_000));
        assert_eq!(nice_scale(1_001), (500, 1_500));
        for max in [1, 3, 9, 11, 49, 51, 999, 12_345, 1_000_000] {
            let (step, top) = nice_scale(max);
            assert!(top >= max, "the top covers {max}");
            assert!(
                top / step <= MAX_GRIDLINES,
                "at most four gridlines for {max}"
            );
            assert_eq!(top % step, 0, "the top is a gridline");
        }
    }

    #[test]
    fn a_ranked_bar_is_its_share_of_the_largest_value_to_one_decimal() {
        assert_eq!(percent_width(1, 3), "33.3%");
        assert_eq!(percent_width(3, 3), "100.0%");
        assert_eq!(percent_width(0, 5), "0.0%");
        assert_eq!(percent_width(5, 0), "0.0%", "no largest value means no bar");
        assert_eq!(percent_width(2, 3), "66.7%");
    }

    #[test]
    fn a_run_of_values_breaks_at_a_missing_bucket() {
        let buckets = [
            bucket("a", Some(1)),
            bucket("b", None),
            bucket("c", Some(2)),
            bucket("d", Some(3)),
            bucket("e", None),
        ];
        assert_eq!(runs(&buckets), vec![vec![(0, 1)], vec![(2, 2), (3, 3)]]);
    }

    #[test]
    fn at_most_eight_tick_labels_are_written_and_they_are_the_clock_or_the_day() {
        let daily: Vec<Bucket> = (0..90)
            .map(|day| bucket(&format!("2029-10-{:02}", day % 28 + 1), Some(0)))
            .collect();
        let shown = tick_buckets(&daily);
        assert!(shown.len() <= MAX_TICKS, "{} labels", shown.len());
        assert_eq!(shown[0].0, 0);
        assert_eq!(tick_label(&bucket("2029-12-31 23:00", None)), "23:00");
        assert_eq!(tick_label(&bucket("2029-12-31", None)), "12-31");
        assert_eq!(
            tick_buckets(
                &(0..24)
                    .map(|hour| bucket("x", Some(hour)))
                    .collect::<Vec<_>>()
            )
            .len(),
            8
        );
    }
}
