//! One chart on the Overview: its figure with its caption, and the shape's markup. The numbers of
//! a bars or line or ranked chart stand behind a closed Data disclosure.

use form_urlencoded::Serializer;
use maud::{Markup, html};

use super::model::{ChartSpec, GroupBy, Metric, Period, Shape};
use super::query::{Bucket, Category, Scope, Series};
use super::svg;
use crate::web::ui::{breakable, email, thousands};

/// The sentence a chart with no activity in its period shows in place of its figure.
pub const NO_ACTIVITY: &str = "No activity in this period.";

/// The chart as one figure: its title and caption, then its marks, or the sentence that there is no
/// activity in its period.
pub fn chart_section(
    id: i64,
    spec: &ChartSpec,
    title: &str,
    period: Period,
    series: &Series,
    scope: &Scope,
) -> Markup {
    let buckets = match series {
        Series::Buckets(buckets) if !series.is_empty() => Some(buckets.len()),
        _ => None,
    };
    let count = match series {
        Series::Unused(tools) => Some(tools.len()),
        _ => None,
    };
    html! {
        figure.chart id=(format!("chart-{id}")) data-chart=(id) data-shape=(spec.shape.as_str())
            data-width=(spec.width.as_str()) data-tone=[tone(spec.metric)]
            data-buckets=[buckets] {
            figcaption {
                h3 id=(format!("c{id}-title")) {
                    (title)
                    @if let Some(count) = count {
                        " " span.count { (count) }
                    }
                }
                p id=(format!("c{id}-caption")) { (caption(spec, period, scope)) }
            }
            (body(id, spec, title, period, series))
        }
    }
}

/// The marks of a chart by its shape, or the sentence in place of them.
fn body(id: i64, spec: &ChartSpec, title: &str, period: Period, series: &Series) -> Markup {
    let unit = unit_words(spec.metric, true);
    match series {
        Series::Unused(tools) if tools.is_empty() => html! {
            p.chart-empty { "Every listed tool was called in this period." }
        },
        Series::Unused(tools) => unused_table(tools),
        _ if series.is_empty() => html! { p.chart-empty { (NO_ACTIVITY) } },
        Series::Buckets(buckets) => match spec.shape {
            Shape::Table => bucket_table(period, buckets, spec.metric),
            shape => {
                let hourly = period == Period::H24;
                let line = shape == Shape::Line;
                html! {
                    (svg::time_svg(&svg::TimeChart { id, buckets, hourly, unit, line }))
                    (data_details(title, bucket_head(period), &bucket_rows(buckets, spec.metric)))
                }
            }
        },
        Series::Ranked(categories) => match spec.shape {
            Shape::Table => category_table(spec.group_by, spec.metric, categories),
            _ => ranked_figure(title, spec.group_by, spec.metric, categories),
        },
        Series::Number(value) => number_figure(spec.metric, *value),
    }
}

/// The caption: the metric, the split, the limit and the period, in that order.
pub fn caption(spec: &ChartSpec, period: Period, scope: &Scope) -> Markup {
    let split = match spec.group_by {
        GroupBy::Time if period == Period::H24 => " per hour",
        GroupBy::Time => " per day",
        GroupBy::Nothing => "",
        GroupBy::User => " by user",
        GroupBy::Server => " by server",
        GroupBy::Tool => " by tool",
        GroupBy::Client => " by client",
    };
    let limit = match spec.group_by {
        GroupBy::Time | GroupBy::Nothing => String::new(),
        _ => format!(", the top {}", spec.top_n.unwrap_or_default()),
    };
    html! {
        (spec.metric.caption()) (split)
        @if let Some(slug) = &scope.server {
            " on " code { (slug) }
        }
        @if let Some(email) = &scope.user {
            " by " code { (breakable(email)) }
        }
        @if let Some(tool) = &scope.tool {
            " of " code { (breakable(tool)) }
        }
        (limit) ", "
        span.nowrap { (period.words()) }
        @if spec.group_by == GroupBy::Time && period == Period::H24 {
            " (UTC)"
        }
        "."
    }
}

/// The tone of a figure: a refusal or a failure is drawn in the refusal colour.
fn tone(metric: Metric) -> Option<&'static str> {
    match metric {
        Metric::Refused | Metric::Failed | Metric::SignInsRefused => Some("bad"),
        _ => None,
    }
}

/// The unit of a metric's value in words: singular when `plural` is false.
fn unit_words(metric: Metric, plural: bool) -> &'static str {
    match (metric, plural) {
        (Metric::ActiveUsers, true) => "people",
        (Metric::ActiveUsers, false) => "person",
        (Metric::SignIns, true) => "sign-ins",
        (Metric::SignIns, false) => "sign-in",
        (Metric::SignInsRefused, true) => "sign-ins refused",
        (Metric::SignInsRefused, false) => "sign-in refused",
        (Metric::Refused, true) => "tool calls refused",
        (Metric::Refused, false) => "tool call refused",
        (Metric::Failed, true) => "tool calls failed",
        (Metric::Failed, false) => "tool call failed",
        (Metric::DurationMedian | Metric::DurationP95, _) => "ms",
        (_, true) => "tool calls",
        (_, false) => "tool call",
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
fn bucket_table(period: Period, buckets: &[Bucket], metric: Metric) -> Markup {
    data_table(bucket_head(period), &bucket_rows(buckets, metric))
}

/// The label and value of each bucket; a duration bucket with no call says so.
fn bucket_rows(buckets: &[Bucket], metric: Metric) -> Vec<(String, String)> {
    buckets
        .iter()
        .map(|bucket| {
            let value = bucket
                .value
                .map_or_else(|| "No value".to_owned(), |value| shown(metric, value));
            (svg::label_words(&bucket.label), value)
        })
        .collect()
}

/// The ranked list: each name links to the Activity rows behind it, with its value and a bar as wide
/// as its share of the largest.
fn ranked_figure(title: &str, group: GroupBy, metric: Metric, categories: &[Category]) -> Markup {
    let largest = categories
        .iter()
        .map(|category| category.value)
        .max()
        .unwrap_or(0);
    let unit = unit_words(metric, true);
    html! {
        ol.ranked {
            @for category in categories {
                li {
                    (name(group, category))
                    span.ranked-value { (shown(metric, category.value)) }
                    svg.ranked-bar width="100%" height="4" aria-hidden="true" {
                        rect width=(svg::share(category.value, largest)) height="4" {
                            title { (category.label) ": " (thousands(category.value)) " " (unit) }
                        }
                    }
                }
            }
        }
        (data_details(title, group_head(group), &category_rows(categories, metric)))
    }
}

/// A category's name: a link to its rows when it has a key, else plain text. A tool is its server's
/// slug and the tool, each in code.
fn name(group: GroupBy, category: &Category) -> Markup {
    let by = match group {
        GroupBy::User => "user",
        GroupBy::Server => "server",
        GroupBy::Tool => "tool",
        _ => "client",
    };
    let inner = match group {
        GroupBy::Tool => {
            let (slug, tool) = category
                .label
                .split_once(" / ")
                .unwrap_or(("", &category.label));
            html! { code { (slug) } code { (breakable(tool)) } }
        }
        GroupBy::Server => html! { code { (category.label) } },
        GroupBy::User if category.label.contains('@') => email(&category.label),
        _ => html! { (category.label) },
    };
    match &category.link {
        Some(pairs) => html! {
            a.ranked-name data-by=(by) href=(activity_href(pairs)) { (inner) }
        },
        None => html! {
            span.ranked-name data-by=(by) { (inner) }
        },
    }
}

/// A ranked grouping as a table of its names and numbers, the shape `table`.
fn category_table(group: GroupBy, metric: Metric, categories: &[Category]) -> Markup {
    html! {
        table.figures {
            thead {
                tr {
                    th scope="col" { (group_head(group)) }
                    th scope="col" class="num" { "Value" }
                }
            }
            tbody {
                @for category in categories {
                    tr {
                        td { (name(group, category)) }
                        td.num { (shown(metric, category.value)) }
                    }
                }
            }
        }
    }
}

fn group_head(group: GroupBy) -> &'static str {
    match group {
        GroupBy::User => "User",
        GroupBy::Server => "Server",
        GroupBy::Tool => "Tool",
        _ => "Client",
    }
}

fn category_rows(categories: &[Category], metric: Metric) -> Vec<(String, String)> {
    categories
        .iter()
        .map(|category| (category.label.clone(), shown(metric, category.value)))
        .collect()
}

/// A value as the panel writes it: thousands grouped, and a duration with its unit.
fn shown(metric: Metric, value: i64) -> String {
    match metric {
        Metric::DurationMedian | Metric::DurationP95 => format!("{} ms", thousands(value)),
        _ => thousands(value),
    }
}

/// One number with its unit: the count in words, or milliseconds for a duration. A refusal's unit
/// is the refusal tone's span.
fn number_figure(metric: Metric, value: Option<i64>) -> Markup {
    let Some(value) = value else {
        return html! { p.chart-empty { (NO_ACTIVITY) } };
    };
    let unit = unit_words(metric, value != 1);
    html! {
        p.figure-number {
            span.figure-value { (thousands(value)) }
            " "
            @if tone(metric).is_some() {
                span.state data-tone="bad" { (unit) }
            } @else {
                span.figure-unit { (unit) }
            }
        }
    }
}

/// The tools with no call, grouped by server, as a table with no Data disclosure.
fn unused_table(tools: &[(String, String)]) -> Markup {
    html! {
        table.figures.unused {
            thead {
                tr {
                    th scope="col" class="c-server" { "Server" }
                    th scope="col" { "Tool" }
                }
            }
            tbody {
                @for (server, tool) in tools {
                    tr {
                        td { code { (server) } }
                        td { code { (breakable(tool)) } }
                    }
                }
            }
        }
    }
}

/// The numbers of a chart in a closed disclosure under it.
fn data_details(title: &str, head: &str, rows: &[(String, String)]) -> Markup {
    html! {
        details.data {
            summary {
                span.data-open { "Data" span.chevron aria-hidden="true" {} }
            }
            div.data-body tabindex="0" role="group" aria-label=(format!("Data of {title}")) {
                (data_table(head, rows))
            }
        }
    }
}

fn data_table(head: &str, rows: &[(String, String)]) -> Markup {
    html! {
        table.figures {
            thead {
                tr {
                    th scope="col" { (head) }
                    th scope="col" class="num" { "Value" }
                }
            }
            tbody {
                @for (label, value) in rows {
                    tr {
                        td { (label) }
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
    fn the_unit_is_singular_at_one_only() {
        assert_eq!(unit_words(Metric::Calls, false), "tool call");
        assert_eq!(unit_words(Metric::Calls, true), "tool calls");
        assert_eq!(unit_words(Metric::SignInsRefused, false), "sign-in refused");
        assert_eq!(unit_words(Metric::ActiveUsers, true), "people");
    }
}
