//! What a chart and a dashboard may hold: the closed lists, the combinations of their fields, the
//! limits, and the checks a posted form passes before anything is stored.

/// Longest title or dashboard name, in characters, after trimming.
pub const TEXT_LIMIT: usize = 80;
/// Longest tool name a chart may filter to, in characters.
pub const TOOL_LIMIT: usize = 128;
pub const DASHBOARD_LIMIT: i64 = 20;
pub const CHART_LIMIT: i64 = 24;
/// The counts a ranked list or a table of categories may show.
pub const TOP_COUNTS: [i64; 4] = [5, 10, 20, 50];

pub const NAME: &str = "A dashboard needs a name of 1 to 80 characters.";
pub const NAME_TAKEN: &str = "A dashboard with that name already exists.";
pub const DASHBOARD_FULL: &str = "There are 20 dashboards already, the most there can be.";
pub const TITLE: &str = "A chart needs a title of 1 to 80 characters.";
pub const METRIC: &str = "Choose a metric from the list.";
pub const GROUP: &str = "Choose a grouping from the list.";
pub const SHAPE: &str = "Choose a shape from the list.";
pub const PERIOD: &str = "Choose a period from the list.";
pub const WIDTH: &str = "Choose a width from the list.";
pub const SERVER: &str = "Choose a server that exists, or any server.";
pub const USER: &str = "Choose a user that exists, or any user.";
pub const TOOL: &str = "A tool name is 1 to 128 characters.";
pub const TOP: &str = "A ranked chart needs a top count of 5, 10, 20 or 50.";
pub const SHAPE_FIT: &str = "This shape does not fit this grouping: over time, a line, bars or a table; by user, server, tool or client, ranked or a table; with no grouping, a number.";
pub const UNUSED_GROUP: &str = "Unused tools has no grouping: choose none.";
pub const UNUSED_SHAPE: &str = "Unused tools is shown as a table.";
pub const CHART_FULL: &str = "This dashboard has 24 charts already, the most it can hold.";

/// The field a refusal message is about, with the id its control has; None for a limit.
pub fn field_of(message: &str) -> Option<&'static str> {
    match message {
        NAME | NAME_TAKEN => Some("dashboard-name"),
        TITLE => Some("chart-title"),
        METRIC => Some("chart-metric"),
        GROUP | UNUSED_GROUP => Some("chart-group-by"),
        SHAPE | SHAPE_FIT | UNUSED_SHAPE => Some("chart-shape"),
        PERIOD => Some("chart-period"),
        WIDTH => Some("chart-width"),
        SERVER => Some("chart-server"),
        USER => Some("chart-user"),
        TOOL => Some("chart-tool"),
        TOP => Some("chart-top"),
        _ => None,
    }
}

macro_rules! closed_list {
    ($name:ident { $($variant:ident => $key:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Every value, in the order the form lists them.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The key stored and posted for this value.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $key),+
                }
            }

            /// The value a key names; None for any other text.
            pub fn parse(text: &str) -> Option<$name> {
                $name::ALL.iter().copied().find(|value| value.as_str() == text)
            }
        }
    };
}

closed_list!(Metric {
    Calls => "calls",
    Refused => "refused",
    Failed => "failed",
    AllCalls => "all_calls",
    ActiveUsers => "active_users",
    SignIns => "sign_ins",
    SignInsRefused => "sign_ins_refused",
    DurationMedian => "duration_median",
    DurationP95 => "duration_p95",
    UnusedTools => "unused_tools",
});

closed_list!(GroupBy {
    Time => "time",
    User => "user",
    Server => "server",
    Tool => "tool",
    Client => "client",
    Nothing => "none",
});

closed_list!(Shape {
    Line => "line",
    Bars => "bars",
    Ranked => "ranked",
    Number => "number",
    Table => "table",
});

closed_list!(Period {
    H24 => "24h",
    D7 => "7d",
    D30 => "30d",
    D90 => "90d",
});

closed_list!(Width {
    Half => "half",
    Full => "full",
});

impl Metric {
    /// The label of the metric in the builder form.
    pub fn label(self) -> &'static str {
        match self {
            Metric::Calls => "Calls",
            Metric::Refused => "Refused calls",
            Metric::Failed => "Failed calls",
            Metric::AllCalls => "All calls",
            Metric::ActiveUsers => "Active users",
            Metric::SignIns => "Sign-ins",
            Metric::SignInsRefused => "Refused sign-ins",
            Metric::DurationMedian => "Median duration",
            Metric::DurationP95 => "95th percentile duration",
            Metric::UnusedTools => "Unused tools",
        }
    }

    /// What the metric counts, as a caption says it.
    pub fn caption(self) -> &'static str {
        match self {
            Metric::Calls => "Tool calls let through",
            Metric::Refused => "Tool calls refused",
            Metric::Failed => "Tool calls that failed or reported an error",
            Metric::AllCalls => "All tool calls",
            Metric::ActiveUsers => "People with at least one tool call",
            Metric::SignIns => "Sign-ins",
            Metric::SignInsRefused => "Sign-ins refused",
            Metric::DurationMedian => "Median duration of calls let through",
            Metric::DurationP95 => "95th percentile duration of calls let through",
            Metric::UnusedTools => "Tools the servers list that had no call let through",
        }
    }

    /// The percentile a duration metric takes, None for a count.
    pub fn percentile(self) -> Option<i64> {
        match self {
            Metric::DurationMedian => Some(50),
            Metric::DurationP95 => Some(95),
            _ => None,
        }
    }
}

impl GroupBy {
    /// The label of the grouping in the builder form.
    pub fn label(self) -> &'static str {
        match self {
            GroupBy::Time => "Over time",
            GroupBy::User => "User",
            GroupBy::Server => "Server",
            GroupBy::Tool => "Tool",
            GroupBy::Client => "Client",
            GroupBy::Nothing => "None",
        }
    }

    /// Whether the grouping ranks categories and so takes a top count.
    pub fn is_category(self) -> bool {
        matches!(
            self,
            GroupBy::User | GroupBy::Server | GroupBy::Tool | GroupBy::Client
        )
    }
}

impl Shape {
    pub fn label(self) -> &'static str {
        match self {
            Shape::Line => "Line",
            Shape::Bars => "Bars",
            Shape::Ranked => "Ranked list",
            Shape::Number => "Number",
            Shape::Table => "Table",
        }
    }
}

impl Period {
    pub fn label(self) -> &'static str {
        match self {
            Period::H24 => "Last 24 hours",
            Period::D7 => "Last 7 days",
            Period::D30 => "Last 30 days",
            Period::D90 => "Last 90 days",
        }
    }

    /// The period in words, as a caption says it.
    pub fn words(self) -> &'static str {
        match self {
            Period::H24 => "last 24 hours",
            Period::D7 => "last 7 days",
            Period::D30 => "last 30 days",
            Period::D90 => "last 90 days",
        }
    }
}

impl Width {
    pub fn label(self) -> &'static str {
        match self {
            Width::Half => "Half width",
            Width::Full => "Full width",
        }
    }
}

/// The definition of one chart as stored: what it counts, how it is grouped and drawn, and its filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChartSpec {
    pub metric: Metric,
    pub group_by: GroupBy,
    pub shape: Shape,
    pub period: Period,
    pub server_id: Option<i64>,
    pub user_id: Option<i64>,
    pub tool: Option<String>,
    pub top_n: Option<i64>,
    pub width: Width,
}

/// The builder form as the person posted it, each field as text.
#[derive(Clone, Default)]
pub struct Draft {
    pub title: String,
    pub metric: String,
    pub group_by: String,
    pub shape: String,
    pub period: String,
    pub server_id: String,
    pub user_id: String,
    pub tool: String,
    pub top_n: String,
    pub width: String,
}

/// A chart whose fields passed the checks.
pub struct Checked {
    pub title: String,
    pub spec: ChartSpec,
}

/// Trims a name or title and checks its length: 1 to 80 characters.
pub fn check_text(text: &str, refusal: &'static str) -> Result<String, &'static str> {
    let trimmed = text.trim();
    let length = trimmed.chars().count();
    if (1..=TEXT_LIMIT).contains(&length) {
        Ok(trimmed.to_owned())
    } else {
        Err(refusal)
    }
}

/// The name of a dashboard, trimmed and checked.
pub fn check_name(text: &str) -> Result<String, &'static str> {
    check_text(text, NAME)
}

/// Checks the posted chart in the order of the form. The first field that fails names the refusal.
pub fn check_chart(draft: &Draft) -> Result<Checked, &'static str> {
    let title = check_text(&draft.title, TITLE)?;
    let metric = Metric::parse(&draft.metric).ok_or(METRIC)?;
    let group_by = GroupBy::parse(&draft.group_by).ok_or(GROUP)?;
    let shape = Shape::parse(&draft.shape).ok_or(SHAPE)?;
    let period = Period::parse(&draft.period).ok_or(PERIOD)?;
    let width = Width::parse(&draft.width).ok_or(WIDTH)?;
    let server_id = optional_id(&draft.server_id).ok_or(SERVER)?;
    let user_id = optional_id(&draft.user_id).ok_or(USER)?;
    let tool = optional_tool(&draft.tool)?;
    let top_n = top_count(group_by, &draft.top_n)?;
    check_shape(metric, group_by, shape)?;
    Ok(Checked {
        title,
        spec: ChartSpec {
            metric,
            group_by,
            shape,
            period,
            server_id,
            user_id,
            tool,
            top_n,
            width,
        },
    })
}

/// The id a filter names: Some(None) when empty, None when the text is not a number.
fn optional_id(text: &str) -> Option<Option<i64>> {
    let text = text.trim();
    if text.is_empty() {
        Some(None)
    } else {
        text.parse().ok().map(Some)
    }
}

/// The tool a filter names, trimmed; None when empty; refused when longer than 128 characters.
fn optional_tool(text: &str) -> Result<Option<String>, &'static str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else if trimmed.chars().count() <= TOOL_LIMIT {
        Ok(Some(trimmed.to_owned()))
    } else {
        Err(TOOL)
    }
}

/// The top count of a ranked grouping, required there; a top count on any other grouping is ignored.
fn top_count(group_by: GroupBy, text: &str) -> Result<Option<i64>, &'static str> {
    if !group_by.is_category() {
        return Ok(None);
    }
    text.trim()
        .parse::<i64>()
        .ok()
        .filter(|count| TOP_COUNTS.contains(count))
        .map(Some)
        .ok_or(TOP)
}

/// The shapes a metric and a grouping may take together.
fn check_shape(metric: Metric, group_by: GroupBy, shape: Shape) -> Result<(), &'static str> {
    if metric == Metric::UnusedTools {
        if group_by != GroupBy::Nothing {
            return Err(UNUSED_GROUP);
        }
        return if shape == Shape::Table {
            Ok(())
        } else {
            Err(UNUSED_SHAPE)
        };
    }
    let fits = match group_by {
        GroupBy::Time => matches!(shape, Shape::Line | Shape::Bars | Shape::Table),
        GroupBy::User | GroupBy::Server | GroupBy::Tool | GroupBy::Client => {
            matches!(shape, Shape::Ranked | Shape::Table)
        }
        GroupBy::Nothing => shape == Shape::Number,
    };
    if fits { Ok(()) } else { Err(SHAPE_FIT) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(metric: &str, group_by: &str, shape: &str) -> Draft {
        Draft {
            title: "Chart".into(),
            metric: metric.into(),
            group_by: group_by.into(),
            shape: shape.into(),
            period: "30d".into(),
            width: "half".into(),
            top_n: "10".into(),
            ..Draft::default()
        }
    }

    #[test]
    fn every_closed_list_key_parses_back_to_its_value() {
        for metric in Metric::ALL {
            assert_eq!(Metric::parse(metric.as_str()), Some(*metric));
        }
        assert_eq!(GroupBy::parse("none"), Some(GroupBy::Nothing));
        assert_eq!(Shape::parse("pie"), None);
        assert_eq!(Period::parse("all"), None, "all time is not a chart period");
        assert_eq!(Width::parse("Half"), None, "keys are exact");
    }

    #[test]
    fn a_title_is_trimmed_and_1_to_80_characters() {
        assert_eq!(check_text("  Errors  ", TITLE), Ok("Errors".to_owned()));
        assert_eq!(check_text(&"c".repeat(80), TITLE).map(|t| t.len()), Ok(80));
        assert_eq!(check_text(&"c".repeat(81), TITLE), Err(TITLE));
        assert_eq!(check_text(" \t ", TITLE), Err(TITLE));
        assert_eq!(
            check_text(&"é".repeat(80), TITLE).map(|t| t.chars().count()),
            Ok(80),
            "characters, not bytes"
        );
    }

    #[test]
    fn a_valid_combination_is_accepted_and_the_others_refused() {
        for (metric, group, shape) in [
            ("calls", "time", "bars"),
            ("calls", "time", "line"),
            ("calls", "time", "table"),
            ("calls", "user", "ranked"),
            ("calls", "server", "table"),
            ("calls", "none", "number"),
            ("unused_tools", "none", "table"),
        ] {
            let checked = check_chart(&draft(metric, group, shape));
            assert!(checked.is_ok(), "{metric} {group} {shape} is valid");
        }
        for (metric, group, shape, message) in [
            ("calls", "time", "ranked", SHAPE_FIT),
            ("calls", "none", "table", SHAPE_FIT),
            ("calls", "user", "number", SHAPE_FIT),
            ("unused_tools", "time", "table", UNUSED_GROUP),
            ("unused_tools", "none", "number", UNUSED_SHAPE),
        ] {
            let refused = check_chart(&draft(metric, group, shape));
            assert_eq!(refused.err(), Some(message), "{metric} {group} {shape}");
        }
    }

    #[test]
    fn a_ranked_grouping_needs_one_of_the_top_counts_and_other_groupings_drop_it() {
        let mut ranked = draft("calls", "tool", "ranked");
        ranked.top_n = "7".into();
        assert_eq!(check_chart(&ranked).err(), Some(TOP));
        ranked.top_n = String::new();
        assert_eq!(check_chart(&ranked).err(), Some(TOP));
        ranked.top_n = "50".into();
        assert_eq!(
            check_chart(&ranked).ok().map(|c| c.spec.top_n),
            Some(Some(50))
        );
        let time = draft("calls", "time", "bars");
        assert_eq!(check_chart(&time).ok().map(|c| c.spec.top_n), Some(None));
    }

    #[test]
    fn a_filter_that_is_not_an_id_is_refused_and_an_empty_one_is_no_filter() {
        let mut filtered = draft("calls", "none", "number");
        filtered.server_id = "x1".into();
        assert_eq!(check_chart(&filtered).err(), Some(SERVER));
        filtered.server_id = String::new();
        filtered.user_id = " 4 ".into();
        assert_eq!(
            check_chart(&filtered).ok().map(|c| c.spec.user_id),
            Some(Some(4))
        );
    }

    #[test]
    fn every_refusal_names_a_field_and_a_limit_names_none() {
        assert_eq!(field_of(TITLE), Some("chart-title"));
        assert_eq!(field_of(SHAPE_FIT), Some("chart-shape"));
        assert_eq!(field_of(TOP), Some("chart-top"));
        assert_eq!(field_of(NAME_TAKEN), Some("dashboard-name"));
        assert_eq!(field_of(DASHBOARD_FULL), None);
        assert_eq!(field_of(CHART_FULL), None);
    }
}
