//! Server-drawn geometry of the time charts and of the ranked bars. The outer svg of a time chart has
//! no viewBox, so a unit is a CSS pixel: across the plot positions are percentages, down it pixels.

use maud::{Markup, html};

use super::query::Bucket;
use crate::web::ui::thousands;

/// The plot runs from y 20 down to the baseline at y 164: 144 px.
const PLOT_TOP: i64 = 20;
const PLOT_HEIGHT: i64 = 144;
const BASELINE: i64 = 164;
const DATE_Y: i64 = 182;
/// The width of the scale column at the right of a time chart, inside its svg.
const SCALE_COLUMN: i64 = 48;
/// A line tick this close to an edge of the plot hangs inwards; a tick within NEAR_EDGE of it is near.
const EDGE: f64 = 0.04;
const NEAR_EDGE: f64 = 0.24;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// One time chart: its id (its caption is `c{id}-caption`), its buckets, whether they are hours, the
/// unit of a value in words, and whether it is drawn as a line rather than bars.
pub struct TimeChart<'a> {
    pub id: i64,
    pub buckets: &'a [Bucket],
    pub hourly: bool,
    pub weekly: bool,
    pub unit: &'a str,
    pub line: bool,
}

/// The step and the number of steps of a scale: the smallest whole step covering `max` in two to
/// four steps. The top of the scale is their product.
pub fn nice_scale(max: i64) -> (i64, i64) {
    let max = i128::from(max.max(1));
    let mut unit: i128 = 1;
    loop {
        let mut candidates = vec![unit, unit * 2];
        if unit % 2 == 0 {
            candidates.push(unit * 5 / 2);
        }
        candidates.push(unit * 5);
        for step in candidates {
            let steps = (max + step - 1) / step;
            if steps <= 4 {
                return (step as i64, steps.max(2) as i64);
            }
        }
        unit *= 10;
    }
}

/// A value's height above the baseline on a scale of `top`, in whole pixels.
fn height(value: i64, top: i64) -> i64 {
    (PLOT_HEIGHT as f64 * value as f64 / top as f64).round() as i64
}

/// A scale figure: from 100,000 shortened to thousands, from a million to millions.
fn scale_label(value: i64) -> String {
    if value >= 1_000_000 {
        let tenths = (value + 50_000) / 100_000;
        if tenths % 10 == 0 {
            format!("{}M", tenths / 10)
        } else {
            format!("{}.{}M", tenths / 10, tenths % 10)
        }
    } else if value >= 100_000 {
        format!("{}k", (value + 500) / 1_000)
    } else {
        thousands(value)
    }
}

/// The share of each slot a bar leaves empty on either side, by the number of buckets.
fn inset(count: usize) -> f64 {
    if count <= 12 {
        0.2
    } else if count <= 31 {
        0.14
    } else {
        0.1
    }
}

/// A fraction of the plot as a percentage with three decimals.
fn percent(fraction: f64) -> String {
    format!("{:.3}%", fraction * 100.0)
}

/// A bucket's day, and its hour when the chart is hourly.
#[derive(Clone, Copy)]
struct When {
    days: i64,
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
}

impl When {
    /// A bucket label: `YYYY-MM-DD`, or `YYYY-MM-DD HH:MM` for an hour.
    fn of(label: &str) -> Option<When> {
        let (date, clock) = label.split_once(' ').unwrap_or((label, "0:0"));
        let mut parts = date.split('-');
        let year: i64 = parts.next()?.parse().ok()?;
        let month: i64 = parts.next()?.parse().ok()?;
        let day: i64 = parts.next()?.parse().ok()?;
        let hour: i64 = clock.split(':').next()?.parse().ok()?;
        Some(When {
            days: days_from_civil(year, month, day),
            year,
            month,
            day,
            hour,
        })
    }

    /// `18 Nov`.
    fn short(self) -> String {
        format!("{} {}", self.day, MONTHS[(self.month - 1) as usize])
    }

    /// `18 Nov 2026`.
    fn full(self) -> String {
        format!("{} {}", self.short(), self.year)
    }

    /// Whether the day is a Monday; 1970-01-01 was a Thursday.
    fn monday(self) -> bool {
        (self.days + 3).rem_euclid(7) == 0
    }
}

/// The days since 1970-01-01 of a civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A bucket's label in words: `26 Dec 2029`, or `26 Dec 2029 13:00` for an hour.
pub fn label_words(label: &str) -> String {
    match label.split_once(' ') {
        Some((_, clock)) => match When::of(label) {
            Some(when) => format!("{} {clock}", when.full()),
            None => label.to_owned(),
        },
        None => match When::of(label) {
            Some(when) => when.full(),
            None => label.to_owned(),
        },
    }
}

/// The title of a bucket's mark: its day or its hour, and its value in words.
fn mark_title(bucket: &Bucket, hourly: bool, weekly: bool, unit: &str) -> String {
    let when_text = match When::of(&bucket.label) {
        Some(when) if hourly => format!(
            "{} {:02}:00 to {:02}:00 UTC",
            when.full(),
            when.hour,
            (when.hour + 1) % 24
        ),
        Some(when) if weekly => format!("Week from {}", when.full()),
        Some(when) => when.full(),
        None => bucket.label.clone(),
    };
    let text = match bucket.value {
        Some(value) => format!("{when_text}: {} {unit}", thousands(value)),
        None => format!("{when_text}: no value"),
    };
    if bucket.partial {
        format!("{text}, so far")
    } else {
        text
    }
}

/// A date tick: the bucket it stands under, its label, and whether it is minor.
struct Tick {
    index: usize,
    label: String,
    minor: bool,
}

/// The ticks of a time chart: every sixth hour, midnight written as its day; every day of seven,
/// every second one from the newest minor; Mondays up to 31 days; the first of each month beyond.
fn ticks(buckets: &[Bucket], hourly: bool, weekly: bool) -> Vec<Tick> {
    let count = buckets.len();
    let mut out = Vec::new();
    for (index, bucket) in buckets.iter().enumerate() {
        let Some(when) = When::of(&bucket.label) else {
            continue;
        };
        if hourly {
            if when.hour % 6 == 0 {
                let label = if when.hour == 0 {
                    when.short()
                } else {
                    format!("{:02}:00", when.hour)
                };
                out.push(Tick {
                    index,
                    label,
                    minor: false,
                });
            }
        } else if weekly {
            out.push(Tick {
                index,
                label: when.short(),
                minor: false,
            });
        } else if count == 7 {
            let minor = (count - 1 - index) % 2 == 1;
            out.push(Tick {
                index,
                label: when.short(),
                minor,
            });
        } else if count <= 31 {
            if when.monday() {
                out.push(Tick {
                    index,
                    label: when.short(),
                    minor: false,
                });
            }
        } else if when.day == 1 {
            out.push(Tick {
                index,
                label: when.short(),
                minor: false,
            });
        }
    }
    out
}

/// The class of each line tick: an edge tick hangs inwards, and a tick near one is `near-edge`.
fn tick_classes(positions: &[f64]) -> Vec<&'static str> {
    let mut classes: Vec<&'static str> = positions
        .iter()
        .map(|x| {
            if *x < EDGE {
                "edge-start"
            } else if *x > 1.0 - EDGE {
                "edge-end"
            } else {
                ""
            }
        })
        .collect();
    for index in 0..positions.len() {
        if classes[index].is_empty() {
            continue;
        }
        for neighbour in [index.checked_sub(1), index.checked_add(1)]
            .into_iter()
            .flatten()
        {
            let near = positions
                .get(neighbour)
                .is_some_and(|x| (x - positions[index]).abs() < NEAR_EDGE);
            if near && classes[neighbour].is_empty() {
                classes[neighbour] = "near-edge";
            }
        }
    }
    classes
}

/// The runs of consecutive buckets that have a value, as (index, value) pairs.
fn runs(buckets: &[Bucket]) -> Vec<Vec<(usize, i64)>> {
    let mut runs: Vec<Vec<(usize, i64)>> = Vec::new();
    let mut current: Vec<(usize, i64)> = Vec::new();
    for (index, bucket) in buckets.iter().enumerate() {
        match bucket.value.filter(|_| !bucket.partial) {
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

/// The line's points in the nested svg's units: each bucket's centre at its value.
fn line_points(run: &[(usize, i64)], top: i64) -> String {
    run.iter()
        .map(|(index, value)| {
            let y = PLOT_HEIGHT as f64 - PLOT_HEIGHT as f64 * *value as f64 / top as f64;
            format!("{:.1},{:.1}", *index as f64 + 0.5, y)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The class of a date tick's group: its edge or near class, else `minor`, else none.
fn tick_class(edge: &'static str, minor: bool) -> Option<&'static str> {
    if !edge.is_empty() {
        Some(edge)
    } else if minor {
        Some("minor")
    } else {
        None
    }
}

/// The largest value of the buckets, or zero.
fn largest(buckets: &[Bucket]) -> i64 {
    buckets
        .iter()
        .filter_map(|bucket| bucket.value)
        .max()
        .unwrap_or(0)
}

/// The svg of a time chart: the grid, the scale, the marks, the baseline and the date ticks.
pub fn time_svg(chart: &TimeChart<'_>) -> Markup {
    let buckets = chart.buckets;
    let count = buckets.len();
    let (step, steps) = nice_scale(largest(buckets));
    let top = step * steps;
    let grid: Vec<i64> = (1..=steps).map(|k| k * step).collect();
    let inset = inset(count);
    let bar_x = |index: usize| (index as f64 + inset) / count as f64;
    let line_x = |index: usize| (index as f64 + 0.5) / count as f64;
    let tick_list = ticks(buckets, chart.hourly, chart.weekly);
    let positions: Vec<f64> = tick_list
        .iter()
        .map(|tick| {
            if chart.line {
                line_x(tick.index)
            } else {
                bar_x(tick.index)
            }
        })
        .collect();
    let edges: Vec<&'static str> = if chart.line {
        tick_classes(&positions)
    } else {
        vec![""; positions.len()]
    };
    let ticks_out: Vec<(&Tick, f64, Option<&'static str>)> = tick_list
        .iter()
        .zip(positions.iter().zip(edges.iter()))
        .map(|(tick, (x, edge))| (tick, *x, tick_class(edge, tick.minor)))
        .collect();
    let grid_y: Vec<(i64, i64)> = grid
        .iter()
        .map(|value| (*value, BASELINE - height(*value, top)))
        .collect();
    let caption = format!("c{}-caption", chart.id);
    let title = format!("c{}-title", chart.id);
    html! {
        svg.time width="100%" height="188" role="img" aria-labelledby=(format!("{title} {caption}")) {
            g.y aria-hidden="true" {
                text x="100%" y=(BASELINE + 4) { "0" }
                @for (value, y) in &grid_y {
                    text x="100%" y=(y + 4) { (scale_label(*value)) }
                }
            }
            svg.plot-area x="0" y="0" width=(format!("calc(100% - {SCALE_COLUMN}px)")) height="188" overflow="visible" {
                g.grid {
                    @for (_, y) in &grid_y {
                        line x1="0" x2="100%" y1=(format!("{y}.5")) y2=(format!("{y}.5")) {}
                    }
                }
                g.marks {
                    @for (index, bucket) in buckets.iter().enumerate() {
                        g {
                            title { (mark_title(bucket, chart.hourly, chart.weekly, chart.unit)) }
                            rect.hit x=(percent(index as f64 / count as f64)) width=(percent(1.0 / count as f64)) y=(PLOT_TOP) height=(PLOT_HEIGHT) {}
                            @if !chart.line {
                                @if let Some(value) = bucket.value.filter(|value| *value > 0) {
                                    rect class=(if bucket.partial { "chart-bar partial" } else { "chart-bar" }) x=(percent(bar_x(index))) width=(percent((1.0 - 2.0 * inset) / count as f64)) y=(BASELINE - height(value, top).max(1)) height=(height(value, top).max(1)) {}
                                }
                            }
                        }
                    }
                }
                @if chart.line {
                    svg.line x="0" y=(PLOT_TOP) width="100%" height=(PLOT_HEIGHT) viewBox=(format!("0 0 {count} {PLOT_HEIGHT}")) preserveAspectRatio="none" {
                        @for run in runs(buckets) {
                            polyline points=(line_points(&run, top)) {}
                        }
                    }
                }
                line.base x1="0" x2="100%" y1="164.5" y2="164.5" {}
                g.x aria-hidden="true" {
                    @for (tick, x, class) in &ticks_out {
                        g class=[*class] {
                            line x1=(percent(*x)) x2=(percent(*x)) y1="165" y2="169" {}
                            text x=(percent(*x)) y=(DATE_Y) { (tick.label) }
                        }
                    }
                }
            }
        }
    }
}

/// A ranked row's share of the largest value, as a percentage with three decimals; a value above
/// zero is never narrower than 0.4 %.
pub fn share(value: i64, largest: i64) -> String {
    if largest <= 0 {
        return "0.000%".to_owned();
    }
    let fraction = (value as f64 / largest as f64 * 100.0).max(if value > 0 { 0.4 } else { 0.0 });
    format!("{fraction:.3}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(label: &str, value: Option<i64>) -> Bucket {
        Bucket {
            label: label.to_owned(),
            value,
            partial: false,
        }
    }

    #[test]
    fn the_scale_is_the_smallest_whole_step_in_two_to_four_steps() {
        assert_eq!(nice_scale(6_000), (2_000, 3));
        assert_eq!(nice_scale(5_030), (2_000, 3));
        assert_eq!(nice_scale(1), (1, 2));
        assert_eq!(nice_scale(2_000), (500, 4));
    }

    #[test]
    fn a_scale_figure_from_a_hundred_thousand_is_written_short() {
        assert_eq!(scale_label(2_000), "2,000");
        assert_eq!(scale_label(250_000), "250k");
        assert_eq!(scale_label(1_200_000), "1.2M");
    }

    #[test]
    fn a_label_counts_its_days_from_the_epoch_and_knows_a_monday() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert!(When::of("1970-01-05").expect("a day").monday());
        assert_eq!(When::of("2026-11-18").expect("a day").short(), "18 Nov");
    }

    #[test]
    fn a_mark_names_its_day_and_its_value_or_says_there_is_none() {
        assert_eq!(
            mark_title(
                &bucket("2026-11-18", Some(4_826)),
                false,
                false,
                "tool calls"
            ),
            "18 Nov 2026: 4,826 tool calls"
        );
        assert_eq!(
            mark_title(
                &bucket("2026-11-24 13:00", Some(512)),
                true,
                false,
                "tool calls"
            ),
            "24 Nov 2026 13:00 to 14:00 UTC: 512 tool calls"
        );
        assert_eq!(
            mark_title(&bucket("2026-11-18", None), false, false, "ms"),
            "18 Nov 2026: no value"
        );
    }

    #[test]
    fn a_week_mark_names_the_day_it_starts_and_an_open_period_says_so_far() {
        assert_eq!(
            mark_title(&bucket("2026-11-16", Some(9)), false, true, "calls"),
            "Week from 16 Nov 2026: 9 calls"
        );
        let open = Bucket {
            partial: true,
            ..bucket("2026-11-24", Some(3))
        };
        assert_eq!(
            mark_title(&open, false, false, "calls"),
            "24 Nov 2026: 3 calls, so far"
        );
        let open_empty = Bucket {
            partial: true,
            ..bucket("2026-11-24", None)
        };
        assert_eq!(
            mark_title(&open_empty, false, false, "ms"),
            "24 Nov 2026: no value, so far"
        );
    }

    #[test]
    fn a_ranked_share_is_the_value_over_the_largest_and_never_under_0_4_percent() {
        assert_eq!(share(50, 100), "50.000%");
        assert_eq!(share(1, 1_000), "0.400%");
        assert_eq!(share(0, 100), "0.000%");
    }

    #[test]
    fn a_run_of_values_breaks_at_a_missing_bucket() {
        let buckets = [
            bucket("a", Some(1)),
            bucket("b", None),
            bucket("c", Some(2)),
        ];
        assert_eq!(runs(&buckets), vec![vec![(0, 1)], vec![(2, 2)]]);
    }

    #[test]
    fn the_line_stops_at_the_last_complete_bucket() {
        let open = Bucket {
            partial: true,
            ..bucket("today", Some(9))
        };
        let buckets = [bucket("yesterday", Some(4)), open];
        assert_eq!(runs(&buckets), vec![vec![(0, 4)]]);
    }
}
