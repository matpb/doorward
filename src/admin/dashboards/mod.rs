//! Dashboards: sets of charts that belong to the instance. Every admin and the owner edits them, and the
//! Overview shows the chosen one.

mod figure;
mod model;
mod pages;
mod query;
mod store;
mod svg;

pub(super) use pages::{
    get_board, get_list, overview, post_chart_add, post_chart_delete, post_chart_move,
    post_chart_update, post_create, post_delete, post_move, post_rename,
};
