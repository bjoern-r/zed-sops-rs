//! Byte offset <-> LSP position conversion, honouring the negotiated
//! position encoding (UTF-16 by default, UTF-8 if the client offers it).

use tower_lsp_server::ls_types::{Position, Range};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16,
}

pub struct LineIndex<'a> {
    text: &'a str,
    line_starts: Vec<usize>,
    enc: Encoding,
}

impl<'a> LineIndex<'a> {
    pub fn new(text: &'a str, enc: Encoding) -> Self {
        let mut line_starts = vec![0];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { text, line_starts, enc }
    }

    pub fn position(&self, offset: usize) -> Position {
        let offset = offset.min(self.text.len());
        let line = match self.line_starts.binary_search(&offset) {
            Ok(l) => l,
            Err(l) => l - 1,
        };
        let start = self.line_starts[line];
        let slice = &self.text[start..offset];
        let character = match self.enc {
            Encoding::Utf8 => slice.len(),
            Encoding::Utf16 => slice.encode_utf16().count(),
        };
        Position::new(line as u32, character as u32)
    }

    pub fn range(&self, start: usize, end: usize) -> Range {
        Range::new(self.position(start), self.position(end))
    }

    pub fn offset(&self, pos: Position) -> usize {
        let line = pos.line as usize;
        if line >= self.line_starts.len() {
            return self.text.len();
        }
        let start = self.line_starts[line];
        let end = self.line_end(line);
        let line_text = &self.text[start..end];
        let mut units = 0usize;
        for (i, ch) in line_text.char_indices() {
            if units >= pos.character as usize {
                return start + i;
            }
            units += match self.enc {
                Encoding::Utf8 => ch.len_utf8(),
                Encoding::Utf16 => ch.len_utf16(),
            };
        }
        end
    }

    /// Byte offset of the end of `line` (before the newline / CR).
    pub fn line_end(&self, line: usize) -> usize {
        let mut end = self
            .line_starts
            .get(line + 1)
            .map(|s| s - 1)
            .unwrap_or(self.text.len());
        if end > self.line_starts[line] && self.text.as_bytes().get(end - 1) == Some(&b'\r') {
            end -= 1;
        }
        end
    }

    pub fn line_of(&self, offset: usize) -> usize {
        self.position(offset).line as usize
    }

    /// Range covering the entire document.
    pub fn full_range(&self) -> Range {
        Range::new(Position::new(0, 0), self.position(self.text.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_utf16() {
        let t = "a: ä😀x\nb: c\n";
        let idx = LineIndex::new(t, Encoding::Utf16);
        let off = t.find('x').unwrap();
        let p = idx.position(off);
        assert_eq!(p, Position::new(0, 6)); // 'a',':',' ','ä','😀'(2)
        assert_eq!(idx.offset(p), off);
        assert_eq!(idx.position(t.find("b:").unwrap()), Position::new(1, 0));
    }
}
