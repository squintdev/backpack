//! OpenTimestamps wire primitives: 7-bit varints and length-prefixed bytes.

use crate::{Error, Result};

/// Cap on any single varbytes payload — matches python-opentimestamps'
/// MAX limits and keeps a malformed proof from allocating unbounded memory.
pub const MAX_BYTES: usize = 4096;

pub fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(0);
        return;
    }
    while v != 0 {
        let mut b = (v & 0x7f) as u8;
        if v > 0x7f {
            b |= 0x80;
        }
        out.push(b);
        if v <= 0x7f {
            break;
        }
        v >>= 7;
    }
}

pub fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varuint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// A cursor over a serialized proof.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(Error::BadFormat("truncated proof"))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(Error::BadFormat("truncated proof"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn read_varuint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.read_byte()?;
            if shift >= 64 {
                return Err(Error::BadFormat("varint overflow"));
            }
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    pub fn read_varbytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.read_varuint()? as usize;
        if len > max {
            return Err(Error::BadFormat("varbytes too long"));
        }
        self.read_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varuint_roundtrip() {
        for v in [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u32::MAX as u64,
            1 << 40,
        ] {
            let mut buf = Vec::new();
            write_varuint(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(r.read_varuint().unwrap(), v);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn varuint_known_encodings() {
        // Same encoding python-opentimestamps produces.
        let mut buf = Vec::new();
        write_varuint(&mut buf, 0);
        assert_eq!(buf, [0x00]);
        buf.clear();
        write_varuint(&mut buf, 128);
        assert_eq!(buf, [0x80, 0x01]);
    }

    #[test]
    fn varbytes_roundtrip_and_cap() {
        let mut buf = Vec::new();
        write_varbytes(&mut buf, b"hello");
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_varbytes(16).unwrap(), b"hello");

        let mut r = Reader::new(&buf);
        assert!(r.read_varbytes(3).is_err()); // over the cap

        let mut r = Reader::new(&[0x05, b'h', b'i']); // claims 5, has 2
        assert!(r.read_varbytes(16).is_err());
    }
}
