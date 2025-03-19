use crate::tar::*;

impl<'a> AsVal<'a> for File<'a> {
    fn as_src_val(&self) -> (Src<'a>, Val<'a>) {
        let header = &self.header;
        let header = [
            str_raw!(header, name),
            str_int!(header, mode),
            str_int!(header, uid),
            str_int!(header, gid),
            str_int!(header, size),
            str_int!(header, mtime),
            str_int!(header, chksum),
            str_raw!(header, typeflag),
            str_raw!(header, linkname),
        ];
        let ustar = self.header.ustar.as_ref().map(|ustar| {
            [
                str_raw!(ustar, magic),
                str_int!(ustar, version),
                str_raw!(ustar, uname),
                str_raw!(ustar, gname),
                str_int!(ustar, devmajor),
                str_int!(ustar, devminor),
                str_raw!(ustar, prefix),
            ]
        });
        let ustar = ustar.into_iter().flatten();
        let data = [bytes_raw!(self, data)];
        let obj = header.into_iter().chain(ustar).chain(data);
        let obj = Val::Obj(obj.into_iter().collect());
        (Src::Bytes(self.src), obj)
    }
}

#[derive(Debug)]
struct Header<'a> {
    name: &'a str,
    mode: U32<'a>,
    uid: U32<'a>,
    gid: U32<'a>,
    size: U64<'a>,
    mtime: U64<'a>,
    chksum: U32<'a>,
    typeflag: &'a str,
    linkname: &'a str,
    ustar: Option<UStar<'a>>,
}

#[derive(Debug)]
struct UStar<'a> {
    magic: &'a str,
    version: U8<'a>,
    uname: &'a str,
    gname: &'a str,
    devmajor: U32<'a>,
    devminor: U32<'a>,
    prefix: &'a str,
}

fn trim(s: &str) -> &str {
    s.trim_matches(' ')
}

/// Convert a potentially NUL-terminated string to UTF-8.
fn utf8(s: &[u8]) -> &str {
    core::str::from_utf8(s.iter().position(|c| *c == b'\0').map_or(s, |i| &s[..i])).unwrap()
}

#[derive(Debug)]
pub struct File<'a> {
    src: &'a [u8],
    header: Header<'a>,
    data: &'a [u8],
}

fn decode_ustar<'a>(d: &mut &'a [u8]) -> Option<UStar<'a>> {
    let oct8 = |s| (s, u8::from_str_radix(trim(s), 8).unwrap());
    let oct32 = |s| (s, u32::from_str_radix(trim(s), 8).unwrap());
    let magic = match take(d, 6)? {
        ustar @ b"ustar\0" => utf8(ustar),
        _ => return None,
    };
    Some(UStar {
        magic,
        version: oct8(utf8(take(d, 2)?)),
        uname: utf8(take(d, 32)?),
        gname: utf8(take(d, 32)?),
        devmajor: oct32(utf8(take(d, 8)?)),
        devminor: oct32(utf8(take(d, 8)?)),
        prefix: utf8(take(d, 155)?),
    })
}

const BLOCK_BYTES: usize = 512;
const END_MARKER: [u8; BLOCK_BYTES * 2] = [0; BLOCK_BYTES * 2];

fn decode_file<'a>(d: &mut &'a [u8]) -> Option<File<'a>> {
    let src = *d;
    let offset = |d: &[u8]| d.as_ptr() as usize - src.as_ptr() as usize;
    let padding = |pos| BLOCK_BYTES - (pos % BLOCK_BYTES);

    let oct32 = |s| (s, u32::from_str_radix(trim(s), 8).unwrap());
    let oct64 = |s| (s, u64::from_str_radix(trim(s), 8).unwrap());

    let header = Header {
        name: utf8(take(d, 100)?),
        mode: oct32(utf8(take(d, 8)?)),
        uid: oct32(utf8(take(d, 8)?)),
        gid: oct32(utf8(take(d, 8)?)),
        size: oct64(utf8(take(d, 12)?)),
        mtime: oct64(utf8(take(d, 12)?)),
        chksum: oct32(utf8(take(d, 8)?)),
        typeflag: utf8(take(d, 1)?),
        linkname: utf8(take(d, 100)?),
        ustar: decode_ustar(d),
    };
    take(d, padding(offset(d)))?;
    let size: usize = header.size.1.try_into().unwrap();
    let data = take(d, size)?;
    take(d, padding(size))?;
    let src = &src[..BLOCK_BYTES + size + padding(size)];
    Some(File { src, header, data })
}

pub fn decode_tar<'a>(d: &'a mut &'a [u8]) -> impl Iterator<Item = Option<File<'a>>> + 'a {
    core::iter::from_fn(|| (!d.starts_with(&END_MARKER) && !d.is_empty()).then(|| decode_file(d)))
}
