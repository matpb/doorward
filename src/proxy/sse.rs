//! The server-sent event splitter: the data of each complete event, for the catalog and the watched relay.

/// The data of each complete event in `text`, and how many bytes they used up.
/// An event ends at a blank line and a line at LF or CRLF; an event still open is left for later.
pub(crate) fn sse_events(text: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut events = Vec::new();
    let mut used = 0;
    let mut data: Option<Vec<u8>> = None;
    let mut start = 0;
    while let Some(offset) = text[start..].iter().position(|&byte| byte == b'\n') {
        let line = strip_cr(&text[start..start + offset]);
        start += offset + 1;
        if line.is_empty() {
            if let Some(event) = data.take() {
                events.push(event);
            }
            used = start;
        } else if !line.starts_with(b":") {
            let (field, value) = match line.iter().position(|&byte| byte == b':') {
                Some(colon) => (&line[..colon], &line[colon + 1..]),
                None => (line, &line[line.len()..]),
            };
            if field == b"data" {
                let value = value.strip_prefix(b" ").unwrap_or(value);
                match data.as_mut() {
                    Some(buffer) => {
                        buffer.push(b'\n');
                        buffer.extend_from_slice(value);
                    }
                    None => data = Some(value.to_vec()),
                }
            }
        }
    }
    (events, used)
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}
