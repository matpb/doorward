mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::binary::{required_vars, settings_of};
use doorward::Config;
use doorward::config::SETTINGS;
use serde_json::Value;

/// The settings that have no default: a gateway cannot start without them.
const REQUIRED: [&str; 2] = ["public_url", "database"];
const DOCUMENTED_NON_SETTINGS: [&str; 2] = ["DOORWARD_KEY", "DOORWARD_CONFIG"];

/// Reads a file of the repository, or fails naming it.
fn repo_file(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("{relative} must exist and be readable ({err}): package 5C writes it")
    })
}

/// The default of a setting as docs/DOCKER.md must write it.
fn default_text(path: &str, leaves: &BTreeMap<String, Value>) -> String {
    if REQUIRED.contains(&path) {
        return "required".to_owned();
    }
    match &leaves[path] {
        Value::Null => "(none)".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(items) if items.is_empty() => "(none)".to_owned(),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().expect("list entries are text").to_owned())
            .collect::<Vec<String>>()
            .join(", "),
        other => panic!("no default text for {other}"),
    }
}

/// True when a markdown table row holds `variable` and `default` as two of its cells.
fn has_row(docs: &str, variable: &str, default: &str) -> bool {
    docs.lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .any(|line| {
            let cells: Vec<String> = line
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .collect();
            cells.iter().any(|cell| cell == variable) && cells.iter().any(|cell| cell == default)
        })
}

/// Every `DOORWARD_` name in `text`, the prefix included.
fn doorward_names(text: &str) -> Vec<String> {
    const PREFIX: &str = "DOORWARD_";
    text.match_indices(PREFIX)
        .filter_map(|(at, _)| {
            let tail: String = text[at + PREFIX.len()..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            (!tail.is_empty()).then(|| format!("{PREFIX}{tail}"))
        })
        .collect()
}

#[test]
fn every_setting_is_documented_with_its_default() {
    let docs = repo_file("docs/DOCKER.md");
    let defaults =
        Config::from_sources(None, &required_vars()).expect("the required variables load");
    let leaves = settings_of(&defaults);
    for setting in SETTINGS {
        let default = default_text(setting.path, &leaves);
        assert!(
            has_row(&docs, setting.variable, &default),
            "docs/DOCKER.md needs a table row that holds {} and its default {default}",
            setting.variable
        );
    }
}

#[test]
fn no_documented_variable_is_unknown() {
    for file in [
        "docs/DOCKER.md",
        "README.md",
        "compose.yaml",
        "compose.caddy.yaml",
        ".env.example",
    ] {
        let text = repo_file(file);
        for name in doorward_names(&text) {
            let known = DOCUMENTED_NON_SETTINGS.contains(&name.as_str())
                || SETTINGS.iter().any(|setting| setting.variable == name);
            assert!(
                known,
                "{file} names {name}, which is neither a setting, DOORWARD_KEY nor DOORWARD_CONFIG"
            );
        }
    }
}

#[test]
fn the_example_env_file_starts_a_gateway() {
    let text = repo_file(".env.example");
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("doorward.db").display().to_string();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!(".env.example line is not NAME=value: {line}"));
        pairs.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    // The Compose files set the database and the listen address, so the env file
    // may leave them out.
    if !pairs.iter().any(|(name, _)| name == "DOORWARD_DATABASE") {
        pairs.push(("DOORWARD_DATABASE".to_owned(), database.clone()));
    }
    if !pairs.iter().any(|(name, _)| name == "DOORWARD_LISTEN") {
        pairs.push(("DOORWARD_LISTEN".to_owned(), "0.0.0.0:8717".to_owned()));
    }
    for (name, value) in &mut pairs {
        if value.is_empty() {
            match name.as_str() {
                "DOORWARD_PUBLIC_URL" => "https://doorward.example.com".clone_into(value),
                "DOORWARD_DATABASE" => database.clone_into(value),
                _ => {}
            }
        }
    }
    Config::from_sources(None, &pairs)
        .expect("the example env file with its placeholders filled must start a gateway");
}

/// The text of the first ```toml block of `text`, without its fences.
fn first_toml_block(text: &str) -> &str {
    const OPEN: &str = "```toml\n";
    let start = text
        .find(OPEN)
        .unwrap_or_else(|| panic!("README.md must hold a ```toml block"))
        + OPEN.len();
    let length = text[start..]
        .find("\n```")
        .unwrap_or_else(|| panic!("the ```toml block of README.md must be closed"));
    &text[start..start + length]
}

/// The start check of `config`, with a refusal as its message.
fn start_check_of(config: &Config) -> Result<Option<String>, String> {
    config.start_check().map_err(|err| err.to_string())
}

#[test]
fn the_example_config_passes_the_start_check() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("doorward.example.toml");
    let config = Config::load(&path).expect("doorward.example.toml must load");
    assert_eq!(
        start_check_of(&config),
        Ok(None),
        "doorward.example.toml must start: it lists a proxy in trusted_proxies"
    );
}

#[test]
fn the_readme_config_passes_the_start_check() {
    let text = repo_file("README.md");
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("doorward.toml");
    std::fs::write(&path, first_toml_block(&text)).expect("write the README config");
    let config = Config::load(&path).expect("the README config must load");
    assert_eq!(
        start_check_of(&config),
        Ok(None),
        "the README config must start: it lists a proxy in trusted_proxies"
    );
}
