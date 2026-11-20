//! Strict parsing of one JSON value: encoding, repeated keys, lone surrogates, trailing data, depth.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The deepest allowed nesting of arrays and objects.
const MAX_DEPTH: usize = 64;
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Why a body was refused: `Encoding` is JSON-RPC -32600, `Syntax` is -32700.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonRefusal {
    Encoding,
    Syntax,
}

/// One JSON value from the whole input, by the strict rules.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, JsonRefusal> {
    if bytes.starts_with(BOM) {
        return Err(JsonRefusal::Encoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JsonRefusal::Encoding)?;
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Node { enclosing: 0 }
        .deserialize(&mut de)
        .map_err(|_| JsonRefusal::Syntax)?;
    de.end().map_err(|_| JsonRefusal::Syntax)?;
    Ok(value)
}

/// A value that sits inside `enclosing` containers.
struct Node {
    enclosing: usize,
}

impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(Level {
            depth: self.enclosing + 1,
        })
    }
}

/// Builds a value; a container visited here is nested `depth` deep.
struct Level {
    depth: usize,
}

impl Level {
    fn check_depth<E: Error>(&self) -> Result<(), E> {
        if self.depth > MAX_DEPTH {
            return Err(E::custom("nesting too deep"));
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for Level {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        self.check_depth::<A::Error>()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Node {
            enclosing: self.depth,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        self.check_depth::<A::Error>()?;
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(Node {
                enclosing: self.depth,
            })?;
            if object.insert(key, value).is_some() {
                return Err(A::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(object))
    }
}
