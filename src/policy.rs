//! Per-tool access rules: the decision for one call, and the stored rules that can match it.

use std::cmp::Reverse;

use rusqlite::{Connection, params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// One stored rule. `user_id` None is everyone; `server_id` None is all tools; `tool` None is the whole server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub user_id: Option<i64>,
    pub effect: Effect,
    pub server_id: Option<i64>,
    pub tool: Option<String>,
}

/// The answer for one tool, and the rule that decided it: the standing deny when refused,
/// the most specific allow that overrides a deny when allowed, None when no deny matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    pub rule: Option<i64>,
}

/// Scope rank then subject rank: all 0, server 1, tool 2; everyone 0, user 1.
fn rank(rule: &Rule) -> (u8, u8) {
    let scope = match (rule.server_id, rule.tool.is_some()) {
        (None, _) => 0,
        (Some(_), false) => 1,
        (Some(_), true) => 2,
    };
    (scope, u8::from(rule.user_id.is_some()))
}

/// True when the rule's subject and target cover this call.
fn applies(rule: &Rule, user: i64, server: i64, tool: &str) -> bool {
    let subject = rule.user_id.is_none_or(|id| id == user);
    let target = match rule.server_id {
        None => true,
        Some(id) => id == server && rule.tool.as_deref().is_none_or(|name| name == tool),
    };
    subject && target
}

/// True when `allow` is at least as specific as `deny` on both, and strictly more on one.
fn overrides(allow: &Rule, deny: &Rule) -> bool {
    let (a, d) = (rank(allow), rank(deny));
    a.0 >= d.0 && a.1 >= d.1 && (a.0 > d.0 || a.1 > d.1)
}

/// The most specific rule: the highest rank, then the lowest id.
fn most_specific<'a>(rules: impl Iterator<Item = &'a Rule>) -> Option<&'a Rule> {
    rules.min_by_key(|rule| (Reverse(rank(rule)), rule.id))
}

/// Decides one call from the rules given; rules that do not match are ignored.
pub fn decide(rules: &[Rule], user: i64, server: i64, tool: &str) -> Verdict {
    let matching = rules
        .iter()
        .filter(|rule| applies(rule, user, server, tool));
    let (denies, allows): (Vec<&Rule>, Vec<&Rule>) =
        matching.partition(|rule| rule.effect == Effect::Deny);
    let standing: Vec<&Rule> = denies
        .iter()
        .copied()
        .filter(|deny| !allows.iter().any(|allow| overrides(allow, deny)))
        .collect();
    if let Some(deny) = most_specific(standing.into_iter()) {
        return Verdict {
            allowed: false,
            rule: Some(deny.id),
        };
    }
    let overriding = allows
        .iter()
        .copied()
        .filter(|allow| denies.iter().any(|deny| overrides(allow, deny)));
    Verdict {
        allowed: true,
        rule: most_specific(overriding).map(|allow| allow.id),
    }
}

/// The stored rules that can match `user` on `server`: subject everyone or the user, scope all or that server.
pub fn load(conn: &Connection, user: i64, server: i64) -> rusqlite::Result<Vec<Rule>> {
    let mut statement = conn.prepare(
        "SELECT id, user_id, effect, server_id, tool FROM rules \
         WHERE (user_id IS NULL OR user_id = ?1) AND (server_id IS NULL OR server_id = ?2) \
         ORDER BY id",
    )?;
    let rows = statement.query_map(params![user, server], |row| {
        let effect = match row.get::<_, String>(2)?.as_str() {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            _ => {
                return Err(rusqlite::Error::InvalidColumnType(
                    2,
                    "effect".to_owned(),
                    rusqlite::types::Type::Text,
                ));
            }
        };
        Ok(Rule {
            id: row.get(0)?,
            user_id: row.get(1)?,
            effect,
            server_id: row.get(3)?,
            tool: row.get(4)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: i64 = 7;
    const OTHER: i64 = 8;
    const SERVER: i64 = 1;
    const OTHER_SERVER: i64 = 2;
    const TOOL: &str = "echo";

    /// How far a rule reaches: every tool, the whole server, or the one tool.
    #[derive(Clone, Copy, Debug)]
    enum Reach {
        All,
        Server,
        Tool,
    }

    const REACHES: [Reach; 3] = [Reach::All, Reach::Server, Reach::Tool];
    /// `false` is everyone, `true` is ME.
    const SUBJECTS: [bool; 2] = [false, true];

    /// A rule that matches a call by ME to TOOL on SERVER.
    fn rule(id: i64, effect: Effect, reach: Reach, for_me: bool) -> Rule {
        let (server_id, tool) = match reach {
            Reach::All => (None, None),
            Reach::Server => (Some(SERVER), None),
            Reach::Tool => (Some(SERVER), Some(TOOL.to_owned())),
        };
        Rule {
            id,
            user_id: for_me.then_some(ME),
            effect,
            server_id,
            tool,
        }
    }

    fn allowed(rule: Option<i64>) -> Verdict {
        Verdict {
            allowed: true,
            rule,
        }
    }

    fn refused(rule: Option<i64>) -> Verdict {
        Verdict {
            allowed: false,
            rule,
        }
    }

    fn scope_rank(reach: Reach) -> u8 {
        match reach {
            Reach::All => 0,
            Reach::Server => 1,
            Reach::Tool => 2,
        }
    }

    #[test]
    fn with_no_rule_that_matches_the_call_the_tool_is_allowed_and_no_rule_is_named() {
        let cases = [
            ("no rules", Vec::new()),
            (
                "a deny for another user",
                vec![Rule {
                    id: 1,
                    user_id: Some(OTHER),
                    effect: Effect::Deny,
                    server_id: None,
                    tool: None,
                }],
            ),
            (
                "a deny for another server",
                vec![Rule {
                    id: 1,
                    user_id: None,
                    effect: Effect::Deny,
                    server_id: Some(OTHER_SERVER),
                    tool: None,
                }],
            ),
            (
                "a deny for another tool",
                vec![Rule {
                    id: 1,
                    user_id: None,
                    effect: Effect::Deny,
                    server_id: Some(SERVER),
                    tool: Some("search".to_owned()),
                }],
            ),
        ];
        for (case, rules) in cases {
            assert_eq!(
                decide(&rules, ME, SERVER, TOOL),
                allowed(None),
                "{case}: the call is allowed with no rule named"
            );
        }
    }

    #[test]
    fn an_allow_overrides_a_deny_only_when_at_least_as_specific_on_both_and_stricter_on_one() {
        let mut pairs = 0;
        for deny_reach in REACHES {
            for deny_for_me in SUBJECTS {
                for allow_reach in REACHES {
                    for allow_for_me in SUBJECTS {
                        pairs += 1;
                        let deny = rule(1, Effect::Deny, deny_reach, deny_for_me);
                        let allow = rule(2, Effect::Allow, allow_reach, allow_for_me);
                        let (d_scope, a_scope) = (scope_rank(deny_reach), scope_rank(allow_reach));
                        let (d_subject, a_subject) =
                            (u8::from(deny_for_me), u8::from(allow_for_me));
                        let overrides = a_scope >= d_scope
                            && a_subject >= d_subject
                            && (a_scope > d_scope || a_subject > d_subject);
                        let expected = if overrides {
                            allowed(Some(2))
                        } else {
                            refused(Some(1))
                        };
                        assert_eq!(
                            decide(&[deny, allow], ME, SERVER, TOOL),
                            expected,
                            "deny {deny_reach:?} for me {deny_for_me} against allow {allow_reach:?} for me {allow_for_me}"
                        );
                    }
                }
            }
        }
        assert_eq!(
            pairs, 36,
            "every pair of the 3 scopes and 2 subjects is checked"
        );
    }

    #[test]
    fn two_denies_where_one_is_overridden_refuse_and_name_the_standing_one() {
        let rules = [
            rule(1, Effect::Deny, Reach::All, false),
            rule(2, Effect::Deny, Reach::Tool, false),
            rule(3, Effect::Allow, Reach::Server, true),
        ];
        assert_eq!(
            decide(&rules, ME, SERVER, TOOL),
            refused(Some(2)),
            "the tool deny stands because the server allow is less specific in scope"
        );
    }

    #[test]
    fn the_refusal_names_the_most_specific_standing_deny_then_the_lowest_id() {
        let cases = [
            (
                "a tool deny over a server deny",
                vec![
                    rule(5, Effect::Deny, Reach::Server, false),
                    rule(4, Effect::Deny, Reach::Tool, false),
                ],
                4,
            ),
            (
                "a user deny over an everyone deny of the same scope",
                vec![
                    rule(6, Effect::Deny, Reach::Server, false),
                    rule(9, Effect::Deny, Reach::Server, true),
                ],
                9,
            ),
            (
                "equal specificity reports the lowest id",
                vec![
                    rule(12, Effect::Deny, Reach::Tool, true),
                    rule(11, Effect::Deny, Reach::Tool, true),
                ],
                11,
            ),
        ];
        for (case, rules, expected) in cases {
            assert_eq!(
                decide(&rules, ME, SERVER, TOOL),
                refused(Some(expected)),
                "{case}"
            );
        }
    }

    #[test]
    fn an_overridden_deny_reports_the_most_specific_allow_that_overrides_it() {
        let tool_allow_for_everyone_is_not_enough = [
            rule(1, Effect::Deny, Reach::All, true),
            rule(2, Effect::Allow, Reach::Tool, false),
            rule(3, Effect::Allow, Reach::Server, true),
        ];
        assert_eq!(
            decide(&tool_allow_for_everyone_is_not_enough, ME, SERVER, TOOL),
            allowed(Some(3)),
            "the tool allow for everyone does not override the deny for me, so the server allow for me is named"
        );
        let most_specific_wins = [
            rule(1, Effect::Deny, Reach::All, false),
            rule(2, Effect::Allow, Reach::Server, false),
            rule(3, Effect::Allow, Reach::All, true),
            rule(4, Effect::Allow, Reach::Server, true),
        ];
        assert_eq!(
            decide(&most_specific_wins, ME, SERVER, TOOL),
            allowed(Some(4)),
            "the allow that is most specific on scope, then subject, is named"
        );
    }

    #[test]
    fn load_returns_the_everyone_and_all_tools_rules_and_the_users_own_for_that_server() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("doorward.db");
        crate::db::Db::open(&path).expect("database");
        let conn = Connection::open(&path).expect("connection");
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES \
             (7, 'me@example.com', 'hash', 'user', 0), (8, 'other@example.com', 'hash', 'user', 0); \
             INSERT INTO servers (id, name, slug, upstream_url, created_at) VALUES \
             (1, 'one', 'one', 'http://127.0.0.1:9/mcp', 0), \
             (2, 'two', 'two', 'http://127.0.0.1:9/mcp', 0); \
             INSERT INTO rules (id, user_id, effect, server_id, tool, created_at) VALUES \
             (1, NULL, 'deny', NULL, NULL, 0), \
             (2, 8, 'deny', 1, NULL, 0), \
             (3, 7, 'allow', 2, NULL, 0), \
             (4, 7, 'deny', 1, 'echo', 0), \
             (5, NULL, 'allow', 1, NULL, 0), \
             (6, NULL, 'deny', 2, 'echo', 0), \
             (7, 7, 'allow', NULL, NULL, 0);",
        )
        .expect("rules");
        let rule_of = |id: i64,
                       user_id: Option<i64>,
                       effect: Effect,
                       server_id: Option<i64>,
                       tool: Option<&str>| Rule {
            id,
            user_id,
            effect,
            server_id,
            tool: tool.map(str::to_owned),
        };
        let on_one = load(&conn, ME, 1).expect("rules on server one");
        assert_eq!(
            on_one,
            vec![
                rule_of(1, None, Effect::Deny, None, None),
                rule_of(4, Some(ME), Effect::Deny, Some(SERVER), Some("echo")),
                rule_of(5, None, Effect::Allow, Some(SERVER), None),
                rule_of(7, Some(ME), Effect::Allow, None, None),
            ],
            "the rules of other users and other servers are not loaded"
        );
        let on_two = load(&conn, ME, 2).expect("rules on server two");
        assert_eq!(
            on_two.iter().map(|rule| rule.id).collect::<Vec<_>>(),
            vec![1, 3, 6, 7],
            "the rules for server two are loaded, the rules for server one are not"
        );
    }

    #[test]
    fn an_allow_alone_is_allowed_and_names_no_rule() {
        for reach in REACHES {
            for for_me in SUBJECTS {
                assert_eq!(
                    decide(&[rule(1, Effect::Allow, reach, for_me)], ME, SERVER, TOOL),
                    allowed(None),
                    "an allow {reach:?} for me {for_me} alone is allowed with no rule named"
                );
            }
        }
    }
}
