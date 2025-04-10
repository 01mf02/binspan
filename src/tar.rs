use crate::decode::*;
use bytes::Bytes;

fn trim(s: &str) -> &str {
    s.trim_matches(' ')
}

/// Convert a potentially NUL-terminated string to UTF-8.
fn utf8(s: &[u8]) -> &str {
    core::str::from_utf8(s.iter().position(|c| *c == b'\0').map_or(s, |i| &s[..i])).unwrap()
}

fn decode_ustar(o: &mut Obj, b: &mut Bytes) -> Result {
    o.add("magic", raw(b, 6))?;
    o.add("version", take_oct8(b))?;
    o.add("uname", take_str(b, 32))?;
    o.add("gname", take_str(b, 32))?;
    o.add("devmajor", take_oct32(b))?;
    o.add("devminor", take_oct32(b))?;
    o.add("prefix", take_str(b, 155))?;
    Ok(())
}

const BLOCK_BYTES: usize = 512;
const END_MARKER: [u8; BLOCK_BYTES * 2] = [0; BLOCK_BYTES * 2];

fn take_str(b: &mut Bytes, n: usize) -> Result<Decoded<String>> {
    let b = take(b, n)?;
    let s = utf8(&b);
    Ok((Meta::from(&b), Val::Str(s.into()), s.into()))
}

macro_rules! take_oct_str {
    ($name: ident, $ty: ident, $f: expr, $width: expr) => {
        fn $name(b: &mut Bytes) -> Result<Decoded<$ty>> {
            let b = take(b, $width)?;
            let s = utf8(&b);
            let u = $ty::from_str_radix(trim(s), 8).unwrap();
            Ok((Meta::from(b), $f(u), u))
        }
    };
}
take_oct_str!(take_oct8, u8, Val::U8, 2);
take_oct_str!(take_oct32, u32, Val::U32, 8);
take_oct_str!(take_oct64, u64, Val::U64, 12);

fn decode_file<'a>(o: &mut Obj, b: &mut Bytes) -> Result {
    let init = b.clone();
    let offset = |b: &[u8]| b.as_ptr() as usize - init.as_ptr() as usize;
    let padding = |b: &[u8]| BLOCK_BYTES - (offset(b) % BLOCK_BYTES);

    o.add("name", take_str(b, 100))?;
    o.add("mode", take_oct32(b))?;
    o.add("uid", take_oct32(b))?;
    o.add("gid", take_oct32(b))?;
    let size = o.add("size", take_oct64(b))?;
    o.add("mtime", take_oct64(b))?;
    o.add("chksum", take_oct32(b))?;
    o.add("typeflag", take_str(b, 1))?;
    o.add("linkname", take_str(b, 100))?;
    if b.starts_with(b"ustar\0") {
        o.add_consumed("ustar", b, |b, v| decode_ustar(v.make_obj(), b))?;
    }
    o.add("header_block_padding", raw(b, padding(b)))?;
    let size: usize = size.try_into().unwrap();
    o.add("data", raw(b, size))?;
    o.add("data_block_padding", raw(b, padding(b)))?;
    Ok(())
}

pub fn decode_tar(o: &mut Obj, mut b: Bytes) -> Result {
    o.add_consumed("files", &mut b, |b, a| {
        let a = a.make_arr();
        while !b.starts_with(&END_MARKER) && !b.is_empty() {
            a.add_consumed(b, |b, o| decode_file(o.make_obj(), b))?;
        }
        Ok(())
    })?;
    // TODO: if !b.is_empty(), check presence of end marker
    Ok(())
}
