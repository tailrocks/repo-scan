//! Streaming JSON writer with bounded memory (spec §§15–16).
//!
//! A report is framed manually (`{`, fields, arrays) while each record is
//! serialized independently with `serde_json`. Only one record is
//! serialized at a time, so a long report never forces all records into
//! memory and never pins unbounded WAL growth behind a buffered DOM.

use serde::Serialize;

/// Incremental JSON object/array writer. Commas are tracked with an
/// explicit frame stack; every string is escaped by `serde_json`, so no
/// raw framing input can break the document.
pub struct StreamingWriter<W: std::io::Write> {
    writer: W,
    stack: Vec<Frame>,
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Object,
    Array,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    kind: FrameKind,
    first: bool,
}

impl<W: std::io::Write> StreamingWriter<W> {
    /// Wrap a writer. Call [`StreamingWriter::begin_object`] first.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            stack: Vec::new(),
            closed: false,
        }
    }

    /// Open the root object. Must be the first call.
    pub fn begin_object(&mut self) -> crate::Result<()> {
        if !self.stack.is_empty() {
            return Err(crate::Error::Report(
                "streaming writer: begin_object is only valid at the root".to_string(),
            ));
        }
        self.stack.push(Frame {
            kind: FrameKind::Object,
            first: true,
        });
        self.write_byte(b'{')?;
        Ok(())
    }

    /// Write one scalar field (`"name": value) in the current object.
    pub fn field<T: Serialize>(&mut self, name: &str, value: &T) -> crate::Result<()> {
        self.field_separator()?;
        let name_json = serde_json::to_string(name).map_err(|e| {
            crate::Error::Report(format!("streaming writer: field name failed: {e}"))
        })?;
        self.write_all(name_json.as_bytes())?;
        self.write_byte(b':')?;
        self.write_value(value)?;
        Ok(())
    }

    /// Open an array field (`"name": [`). Items follow with
    /// [`StreamingWriter::array_item`], then [`StreamingWriter::end_array`].
    pub fn begin_array_field(&mut self, name: &str) -> crate::Result<()> {
        self.field_separator()?;
        let name_json = serde_json::to_string(name).map_err(|e| {
            crate::Error::Report(format!("streaming writer: array name failed: {e}"))
        })?;
        self.write_all(name_json.as_bytes())?;
        self.write_all(b":[")?;
        self.stack.push(Frame {
            kind: FrameKind::Array,
            first: true,
        });
        Ok(())
    }

    /// Write one array item. Only the item is serialized here, so memory
    /// stays bounded by the largest single record, not the array.
    pub fn array_item<T: Serialize>(&mut self, value: &T) -> crate::Result<()> {
        match self.stack.last_mut() {
            Some(frame) if frame.kind == FrameKind::Array => {
                if frame.first {
                    frame.first = false;
                } else {
                    self.write_byte(b',')?;
                }
                self.write_value(value)?;
                Ok(())
            }
            _ => Err(crate::Error::Report(
                "streaming writer: array_item outside an array".to_string(),
            )),
        }
    }

    /// Close the current array (`]`).
    pub fn end_array(&mut self) -> crate::Result<()> {
        match self.stack.pop() {
            Some(frame) if frame.kind == FrameKind::Array => {
                self.write_byte(b']')?;
                Ok(())
            }
            _ => Err(crate::Error::Report(
                "streaming writer: end_array without an open array".to_string(),
            )),
        }
    }

    /// Close the root object and finish the document. No further calls.
    pub fn end_object(&mut self) -> crate::Result<()> {
        if self.stack.len() != 1 || self.stack[0].kind != FrameKind::Object {
            return Err(crate::Error::Report(
                "streaming writer: end_object with unbalanced frames".to_string(),
            ));
        }
        self.stack.pop();
        self.write_byte(b'}')?;
        self.closed = true;
        Ok(())
    }

    /// Flush and return the inner writer. The document must be closed.
    pub fn finish(mut self) -> crate::Result<W> {
        if !self.closed {
            return Err(crate::Error::Report(
                "streaming writer: finish before end_object".to_string(),
            ));
        }
        self.writer.flush()?;
        Ok(self.writer)
    }

    fn field_separator(&mut self) -> crate::Result<()> {
        match self.stack.last_mut() {
            Some(frame) if frame.kind == FrameKind::Object => {
                if frame.first {
                    frame.first = false;
                } else {
                    self.write_byte(b',')?;
                }
                Ok(())
            }
            _ => Err(crate::Error::Report(
                "streaming writer: field outside an object".to_string(),
            )),
        }
    }

    fn write_value<T: Serialize>(&mut self, value: &T) -> crate::Result<()> {
        serde_json::to_writer(&mut self.writer, value)
            .map_err(|e| crate::Error::Report(format!("streaming writer: serialize failed: {e}")))
    }

    fn write_byte(&mut self, byte: u8) -> crate::Result<()> {
        self.write_all(std::slice::from_ref(&byte))
    }

    fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
        self.writer.write_all(bytes).map_err(crate::Error::from)
    }
}

/// Stream a fully built [`crate::report::model::Report`] through the
/// bounded-memory writer. The records are still serialized one at a time;
/// callers holding every record in memory should prefer streaming straight
/// from the catalog (see `builder`) for large reports.
pub fn write_report_value<W: std::io::Write>(
    writer: W,
    report: &crate::report::model::Report,
) -> crate::Result<W> {
    let mut stream = StreamingWriter::new(writer);
    stream.begin_object()?;
    stream.field("schema_version", &report.schema_version)?;
    stream.field("report_id", &report.report_id)?;
    stream.field("created_at", &report.created_at)?;
    stream.field("tool", &report.tool)?;
    stream.field("scan", &report.scan)?;
    stream.field("coverage", &report.coverage)?;
    stream.field("resources", &report.resources)?;
    write_array(&mut stream, "volumes", &report.volumes)?;
    write_array(&mut stream, "paths", &report.paths)?;
    write_array(&mut stream, "roots", &report.roots)?;
    write_array(&mut stream, "groups", &report.groups)?;
    write_array(&mut stream, "repositories", &report.repositories)?;
    write_array(&mut stream, "checkouts", &report.checkouts)?;
    write_array(&mut stream, "branches", &report.branches)?;
    write_array(&mut stream, "remotes", &report.remotes)?;
    write_array(&mut stream, "storage_links", &report.storage_links)?;
    write_array(&mut stream, "aliases", &report.aliases)?;
    write_array(&mut stream, "candidates", &report.candidates)?;
    write_array(&mut stream, "errors", &report.errors)?;
    write_array(
        &mut stream,
        "generated_artifacts",
        &report.generated_artifacts,
    )?;
    stream.field("totals", &report.totals)?;
    stream.end_object()?;
    stream.finish()
}

/// Write one array field from a slice, one item at a time.
fn write_array<W: std::io::Write, T: Serialize>(
    stream: &mut StreamingWriter<W>,
    name: &str,
    items: &[T],
) -> crate::Result<()> {
    stream.begin_array_field(name)?;
    for item in items {
        stream.array_item(item)?;
    }
    stream.end_array()
}
