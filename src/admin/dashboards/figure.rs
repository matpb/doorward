//! One chart on the Overview: its heading, its caption and its figure, with the Data table of the same
//! numbers. Each shape's markup is one function.

use form_urlencoded::Serializer;
use maud::{Markup, html};

use super::model::{ChartSpec, GroupBy, Metric, Period, Shape};
use super::query::{Bucket, Category, Series};
use super::svg;

/// The sentence a chart with no activity in its period shows in place of its figure.
pub const NO_ACTIVITY: &str = "No activity in this period.";

/// The chart as one section: its heading, its caption, and its figure or the sentence that there is no activity.
pub fn chart_section(
    id: i64,
    spec: &ChartSpec,
    title: &str,
    period: Period,
    series: &Series,
) -> Markup {
    html! {
        section.chart data-chart-id=(id) data-shape=(spec.shape.as_str()) data-width=(spec.width.as_str()) {
            h3 { (title) }
            p.chart-caption { (caption(spec, period)) }
            @if series.is_empty() {
                p.muted { (NO_ACTIVITY) }
            } @else {
                (figure(title, spec, period, series))
            }
        }
    }
}

/// The caption: what the chart counts, the period in words, and how it is grouped.
fn caption(spec: &ChartSpec, period: Period) -> String {
    let mut parts = vec![spec.metric.caption().to_owned(), period.words().to_owned()];
    match spec.group_by {
        GroupBy::Time if period == Period::H24 => parts.push("per hour, UTC".to_owned()),
        GroupBy::Time => parts.push("per day, UTC".to_owned()),
        GroupBy::Nothing => {}
        group => parts.push(format!(
            "the top {} {}",
            spec.top_n.unwrap_or_default(),
            category_noun(group)
        )),
    }
    format!("{}.", parts.join(", "))
}

fn category_noun(group: GroupBy) -> &'static str {
    match group {
        GroupBy::User => "users",
        GroupBy::Server => "servers",
        GroupBy::Tool => "tools",
        _ => "clients",
    }
}

/// The figure of a chart by its shape, with its Data table where the shape has one.
fn figure(title: &str, spec: &ChartSpec, period: Period, series: &Series) -> Markup {
    match series {
        Series::Buckets(buckets) => match spec.shape {
            Shape::Line => line_figure(title, buckets, period),
            Shape::Bars => bars_figure(title, buckets, period),
            _ => bucket_table(period, buckets),
        },
        Series::Ranked(categories) => match spec.shape {
            Shape::Table => category_table(spec.group_by, categories),
            _ => ranked_figure(spec.group_by, categories),
        },
        Series::Number(value) => number_figure(spec.metric, *value),
        Series::Unused(tools) => unused_table(tools),
    }
}

fn line_figure(title: &str, buckets: &[Bucket], period: Period) -> Markup {
    html! {
        div.chart-figure {
            (svg::line(title, buckets))
        }
        (data_details(bucket_head(period), &bucket_rows(buckets)))
    }
}

fn bars_figure(title: &str, buckets: &[Bucket], period: Period) -> Markup {
    html! {
        div.chart-figure {
            (svg::bars(title, buckets))
        }
        (data_details(bucket_head(period), &bucket_rows(buckets)))
    }
}

fn bucket_head(period: Period) -> &'static str {
    if period == Period::H24 {
        "Hour (UTC)"
    } else {
        "Day (UTC)"
    }
}

/// A time chart as a plain table, the shape `table`.
fn bucket_table(period: Period, buckets: &[Bucket]) -> Markup {
    data_table(bucket_head(period), &bucket_rows(buckets))
}

/// The label and value of each bucket; a duration bucket with no call says so.
fn bucket_rows(buckets: &[Bucket]) -> Vec<(String, String)> {
    buckets
        .iter()
        .map(|bucket| {
            let value = bucket
                .value
                .map_or_else(|| "No value".to_owned(), thousands);
            (bucket.label.clone(), value)
        })
        .collect()
}

/// The ranked list: each label links to the Activity rows behind it, its value, and a bar as wide as its share.
fn ranked_figure(group: GroupBy, categories: &[Category]) -> Markup {
    let largest = categories
        .iter()
        .map(|category| category.value)
        .max()
        .unwrap_or(0);
    html! {
        ol.ranked {
            @for category in categories {
                li {
                    a href=(activity_href(&category.link)) { (category.label) }
                    span.rank-value { (thousands(category.value)) }
                    svg.rank-bar viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false" {
                        rect.rank-fill x="0" y="0" width=(svg::percent_width(category.value, largest)) height="8" {}
                    }
                }
            }
        }
        (data_details(group_head(group), &category_rows(categories)))
    }
}

/// A ranked grouping as a plain table, the shape `table`.
fn category_table(group: GroupBy, categories: &[Category]) -> Markup {
    data_table(group_head(group), &category_rows(categories))
}

fn group_head(group: GroupBy) -> &'static str {
    match group {
        GroupBy::User => "User",
        GroupBy::Server => "Server",
        GroupBy::Tool => "Tool",
        _ => "Client",
    }
}

fn category_rows(categories: &[Category]) -> Vec<(String, String)> {
    categories
        .iter()
        .map(|category| (category.label.clone(), thousands(category.value)))
        .collect()
}

/// One number with its unit: the count in words, or milliseconds for a duration.
fn number_figure(metric: Metric, value: Option<i64>) -> Markup {
    let Some(value) = value else {
        return html! { p.muted { (NO_ACTIVITY) } };
    };
    let unit = match metric {
        Metric::DurationMedian | Metric::DurationP95 => "ms",
        other => count_word(other, value),
    };
    html! {
        p.chart-number {
            (thousands(value))
            span.unit { " " (unit) }
        }
    }
}

/// The word after a count: singular at one, plural otherwise.
fn count_word(metric: Metric, value: i64) -> &'static str {
    let one = value == 1;
    match metric {
        Metric::ActiveUsers => {
            if one {
                "user"
            } else {
                "users"
            }
        }
        Metric::SignIns => {
            if one {
                "sign-in"
            } else {
                "sign-ins"
            }
        }
        Metric::SignInsRefused => {
            if one {
                "sign-in refused"
            } else {
                "sign-ins refused"
            }
        }
        Metric::Refused => {
            if one {
                "call refused"
            } else {
                "calls refused"
            }
        }
        Metric::Failed => {
            if one {
                "call failed"
            } else {
                "calls failed"
            }
        }
        _ => {
            if one {
                "call"
            } else {
                "calls"
            }
        }
    }
}

/// The tools with no call, as a plain table of server and tool.
fn unused_table(tools: &[(String, String)]) -> Markup {
    html! {
        table.chart-table {
            thead {
                tr {
                    th scope="col" { "Server" }
                    th scope="col" { "Tool" }
                }
            }
            tbody {
                @for (server, tool) in tools {
                    tr {
                        td { (server) }
                        td { (tool) }
                    }
                }
            }
        }
    }
}

/// The Data table in a closed disclosure under its chart.
fn data_details(head: &str, rows: &[(String, String)]) -> Markup {
    html! {
        details.chart-data {
            summary { "Data" }
            (data_table(head, rows))
        }
    }
}

fn data_table(head: &str, rows: &[(String, String)]) -> Markup {
    html! {
        table.chart-table {
            thead {
                tr {
                    th scope="col" { (head) }
                    th scope="col" class="num" { "Value" }
                }
            }
            tbody {
                @for (label, value) in rows {
                    tr {
                        th scope="row" { (label) }
                        td.num { (value) }
                    }
                }
            }
        }
    }
}

/// The Activity page with the filters of a category, as a path and query.
fn activity_href(pairs: &[(&'static str, String)]) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    format!("/admin/activity?{}", serializer.finish())
}

/// A count with a thousands comma between each group of three digits, a minus sign first if negative.
pub fn thousands(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        out.push('-');
    }
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_gets_a_comma_between_each_group_of_three_digits() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-1_500), "-1,500");
        assert_eq!(thousands(i64::MAX), "9,223,372,036,854,775,807");
    }

    #[test]
    fn the_activity_link_names_each_pair_with_its_value_escaped() {
        let href = activity_href(&[("period", "7d".to_owned()), ("q", "a&b".to_owned())]);
        assert_eq!(href, "/admin/activity?period=7d&q=a%26b");
    }

    #[test]
    fn the_count_word_is_singular_at_one_only() {
        assert_eq!(count_word(Metric::Calls, 1), "call");
        assert_eq!(count_word(Metric::Calls, 2), "calls");
        assert_eq!(count_word(Metric::SignInsRefused, 1), "sign-in refused");
        assert_eq!(
            count_word(Metric::ActiveUsers, 0),
            "users",
            "zero is plural"
        );
    }
}
