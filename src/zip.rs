use bytes::Bytes;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x01\x02";
const LOCAL_FILE_SIG: &[u8; 4] = b"PK\x03\x04";
const END_OF_CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x05\x06";

type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub struct Error {
    position: Bytes,
    path: Vec<Index>,
    expect_len: usize,
    expect_typ: Expect,
}

#[derive(Debug)]
pub enum Index {
    Str(&'static str),
    Int(usize),
}

#[derive(Debug)]
pub enum Expect {
    Bytes,
    Int,
    Raw(&'static [u8]),
}

impl Error {
    fn new(position: Bytes, expect_len: usize) -> Self {
        Self {
            position,
            path: Vec::new(),
            expect_len,
            expect_typ: Expect::Bytes,
        }
    }

    fn with_index(mut self, i: Index) -> Self {
        self.path.push(i);
        self
    }

    fn with_typ(mut self, e: Expect) -> Self {
        self.expect_typ = e;
        self
    }
}

#[derive(Debug, Default)]
pub struct Obj(Vec<(&'static str, Bytes, Val)>);

#[derive(Debug, Default)]
pub struct Arr(Vec<(Bytes, Val)>);

impl Obj {
    fn add_mut<T, F>(&mut self, field: &'static str, b: Bytes, f: F) -> Result<T>
    where
        F: FnOnce(&mut Bytes, &mut Val) -> Result<T>,
    {
        self.0.push((field, b, Val::default()));
        match self.0.last_mut() {
            Some((_, b, v)) => f(b, v).map_err(|e| e.with_index(Index::Str(field))),
            _ => unreachable!(),
        }
    }

    fn add<T>(&mut self, field: &'static str, r: Result<(Bytes, Val, T)>) -> Result<T> {
        let (b, v, y) = r.map_err(|e| e.with_index(Index::Str(field)))?;
        self.0.push((field, b, v));
        Ok(y)
    }
}

impl Arr {
    fn add_mut<T, F>(&mut self, b: Bytes, f: F) -> Result<T>
    where
        F: FnOnce(&mut Bytes, &mut Val) -> Result<T>,
    {
        let i = self.0.len();
        self.0.push((b, Val::default()));
        match self.0.last_mut() {
            Some((b, v)) => f(b, v).map_err(|e| e.with_index(Index::Int(i))),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub enum Atom {
    Bool(bool),
    U16(u16),
    U32(u32),
    Str(String),
    Raw,
}

#[derive(Debug)]
pub enum Val {
    Arr(Arr),
    Obj(Obj),
    Atom(Atom /*, Option<Box<Val>>*/),
    Fun(fn(Bytes) -> Val),
}

impl Default for Val {
    fn default() -> Self {
        Atom::Raw.into()
    }
}

impl Val {
    fn make_arr(&mut self) -> &mut Arr {
        *self = Val::Arr(Arr::default());
        match self {
            Val::Arr(a) => a,
            _ => panic!(),
        }
    }

    fn make_obj(&mut self) -> &mut Obj {
        *self = Val::Obj(Obj::default());
        match self {
            Val::Obj(o) => o,
            _ => panic!(),
        }
    }
}

impl From<Atom> for Val {
    fn from(a: Atom) -> Self {
        Self::Atom(a /*, None*/)
    }
}

fn take(b: &mut Bytes, n: usize) -> Result<Bytes> {
    if n > b.len() {
        Err(Error::new(b.clone(), n))
    } else {
        let b_ = b.slice(..n);
        *b = b.slice(n..);
        Ok(b_)
    }
}

fn consumed<T>(b: &mut Bytes, f: impl FnOnce(&mut Bytes) -> Result<T>) -> Result<(Bytes, T)> {
    let mut start = b.clone();
    let y = f(b)?;
    start.truncate(start.len() - b.len());
    Ok((start, y))
}

fn set_consumed<T>(b: &mut Bytes, f: impl FnOnce(&mut Bytes) -> Result<T>) -> Result<T> {
    let (consumed, y) = consumed(b, f)?;
    *b = consumed;
    Ok(y)
}

fn u16_le(b: &mut Bytes) -> Result<(Bytes, Val, u16)> {
    let b = take(b, 2).map_err(|e| e.with_typ(Expect::Int))?;
    let u = u16::from_le_bytes((*b).try_into().unwrap());
    Ok((b, Atom::U16(u).into(), u))
}

fn u32_le(b: &mut Bytes) -> Result<(Bytes, Val, u32)> {
    let b = take(b, 4).map_err(|e| e.with_typ(Expect::Int))?;
    let u = u32::from_le_bytes((*b).try_into().unwrap());
    Ok((b, Atom::U32(u).into(), u))
}

fn raw(b: &mut Bytes, n: usize) -> Result<(Bytes, Val, ())> {
    Ok((take(b, n)?, Atom::Raw.into(), ()))
}

fn precise(b: &mut Bytes, s: &'static [u8]) -> Result<(Bytes, Val, ())> {
    let err = move |e: Error| e.with_typ(Expect::Raw(s));
    let b = take(b, s.len()).map_err(err)?;
    if b == s {
        Ok((b, Atom::Raw.into(), ()))
    } else {
        Err(err(Error::new(b, s.len())))
    }
}

#[derive(Debug)]
struct EndOfCentralDirRecord {
    disk_nr: u16,
    size_cd: u32,
    offset_cd: u32,
}

impl EndOfCentralDirRecord {
    fn cd_range(&self) -> core::ops::Range<usize> {
        let cd_start: usize = self.offset_cd.try_into().unwrap();
        let cd_len: usize = self.size_cd.try_into().unwrap();
        cd_start..cd_start + cd_len
    }
}

fn decode_eocd(o: &mut Obj, b: &mut Bytes) -> Result<EndOfCentralDirRecord> {
    o.add("signature", precise(b, END_OF_CENTRAL_DIR_SIG))?;
    let disk_nr = o.add("disk_nr", u16_le(b))?;
    o.add("start_disk_nr", u16_le(b))?;
    o.add("nr_of_central_dir_records_on_disk", u16_le(b))?;
    o.add("nr_of_central_dir_records", u16_le(b))?;
    let size_cd = o.add("size_of_central_dir", u32_le(b))?;
    let offset_cd = o.add("offset_of_start_of_central_dir", u32_le(b))?;
    let comment_length = o.add("comment_length", u16_le(b))?;
    o.add("comment", raw(b, comment_length.into()))?;
    Ok(EndOfCentralDirRecord {
        disk_nr,
        size_cd,
        offset_cd,
    })
}

#[derive(Debug)]
struct Common {
    compression_method: u16,
    compressed_size: u32,
    filename_len: u16,
    extra_field_len: u16,
}

#[derive(Debug, FromPrimitive)]
enum CompressionMethod {
    None = 0,
    Shrunk = 1,
    ReducedCompressionFactor1 = 2,
    ReducedCompressionFactor2 = 3,
    ReducedCompressionFactor3 = 4,
    ReducedCompressionFactor4 = 5,
    Imploded = 6,
    Deflated = 8,
    EnhancedDeflated = 9,
    PKWareDCLImploded = 10,
    Bzip2 = 12,
    LZMA = 14,
    IBMTERSE = 18,
    IBMLZ77z = 19,
    PPMd = 98,
}

impl CompressionMethod {
    fn as_str(&self) -> &'static str {
        use CompressionMethod::*;
        match self {
            None => "none",
            Shrunk => "shrunk",
            ReducedCompressionFactor1 => "reduced_compression_factor1",
            ReducedCompressionFactor2 => "reduced_compression_factor2",
            ReducedCompressionFactor3 => "reduced_compression_factor3",
            ReducedCompressionFactor4 => "reduced_compression_factor4",
            Imploded => "imploded",
            Deflated => "deflated",
            EnhancedDeflated => "enhanced_deflated",
            PKWareDCLImploded => "pk_ware_dcl_imploded",
            Bzip2 => "bzip2",
            LZMA => "lzma",
            IBMTERSE => "ibmterse",
            IBMLZ77z => "ibmlz77z",
            PPMd => "pp_md",
        }
    }
}

fn decode_common(o: &mut Obj, b: &mut Bytes) -> Result<Common> {
    o.add("version_needed", u16_le(b))?;
    o.add("flags", raw(b, 2))?;
    let compression_method = o.add("compression_method", u16_le(b))?;
    o.add("last_modification_time", u16_le(b))?;
    o.add("last_modification_date", u16_le(b))?;
    o.add("crc_32", u32_le(b))?;
    let compressed_size = o.add("compressed_size", u32_le(b))?;
    o.add("uncompressed_size", u32_le(b))?;
    let filename_len = o.add("file_name_length", u16_le(b))?;
    let extra_field_len = o.add("extra_field_length", u16_le(b))?;
    Ok(Common {
        compression_method,
        compressed_size,
        filename_len,
        extra_field_len,
    })
}

#[derive(Debug)]
struct CentralDirRecord {
    disk_nr_start: u16,
    local_file_offset: u32,
}

fn decode_cdr(o: &mut Obj, b: &mut Bytes) -> Result<CentralDirRecord> {
    o.add("signature", precise(b, CENTRAL_DIR_SIG))?;
    o.add("version_made_by", u16_le(b))?;
    let common = decode_common(o, b)?;

    let file_comment_len = o.add("file_comment_length", u16_le(b))?;
    let disk_nr_start = o.add("disk_number_where_file_starts", u16_le(b))?;
    o.add("internal_file_attributes", u16_le(b))?;
    o.add("external_file_attributes", u32_le(b))?;
    let local_file_offset = o.add("relative_offset_of_local_file_header", u32_le(b))?;

    o.add("file_name", raw(b, common.filename_len.into()))?;
    o.add("extra_fields", raw(b, common.extra_field_len.into()))?;
    o.add("file_comment", raw(b, file_comment_len.into()))?;

    Ok(CentralDirRecord {
        disk_nr_start,
        local_file_offset,
    })
}

fn deflate(b: &mut Bytes) -> Result<Vec<u8>> {
    use miniz_oxide::inflate::stream::{inflate, InflateState};
    use miniz_oxide::{DataFormat, MZFlush, MZStatus};
    let mut state = InflateState::new(DataFormat::Raw);
    let mut output = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let result = inflate(&mut state, b, &mut buf, MZFlush::None);
        *b = b.slice(result.bytes_consumed..);
        output.extend_from_slice(&buf[..result.bytes_written]);
        if matches!(result.status.unwrap(), MZStatus::StreamEnd) {
            return Ok(output);
        }
    }
}

fn decode_local_file(o: &mut Obj, b: &mut Bytes) -> Result<()> {
    o.add("signature", precise(b, LOCAL_FILE_SIG))?;
    let common = decode_common(o, b)?;

    o.add("file_name", raw(b, common.filename_len.into()))?;
    o.add("extra_fields", raw(b, common.extra_field_len.into()))?;
    // no file_comment here (unlike in central directory)

    let compressed_size = common.compressed_size.try_into().unwrap();
    let add_raw = |o: &mut Obj, field, b| o.add(field, Ok((b, Atom::Raw.into(), ())));
    match CompressionMethod::from_u16(common.compression_method) {
        Some(CompressionMethod::Deflated) => {
            let (compressed, uncompressed) = consumed(b, deflate)?;
            add_raw(o, "compressed", compressed)?;
            add_raw(o, "uncompressed", uncompressed.into())?;
        }
        Some(CompressionMethod::None) => {
            let (compressed, v, ()) = raw(b, compressed_size)?;
            add_raw(o, "compressed", compressed.clone())?;
            add_raw(o, "uncompressed", compressed)?;
        }
        _ if compressed_size != 0 => o.add("compressed", raw(b, compressed_size))?,
        _ => (),
    };

    // TODO: read data descriptor
    Ok(())
}

fn decode_extra_field(o: &mut Obj, b: &mut Bytes) -> Result<()> {
    o.add("tag", u16_le(b))?;
    let size = o.add("size", u16_le(b))?;
    o.add("data", raw(b, size.into()))?;
    Ok(())
}

fn find_eocds(b: &[u8]) -> Option<usize> {
    let is_eocds = |w| w == END_OF_CENTRAL_DIR_SIG;
    Some(b.len() - (b.windows(4).rev().take(128).position(is_eocds)? + 4))
}

// TODO: slice() may panic!
pub fn decode_zip(root: &mut Obj, b: Bytes) -> Result<()> {
    //let offset = |small: &Bytes| dbg!(small.as_ptr() as usize) - dbg!(b.as_ptr() as usize);
    let eocds_abs = find_eocds(&b).unwrap();
    let eocd_slice = || b.slice(eocds_abs..);
    let eocd = root.add_mut("end_of_central_dir_record", eocd_slice(), |_, eocd| {
        decode_eocd(eocd.make_obj(), &mut eocd_slice())
    })?;

    let mut cd_slice = b.slice(eocd.cd_range());
    let cd = root.add_mut("central_directories", cd_slice.clone(), |_, cd| {
        let cd = cd.make_arr();
        let mut cds = Vec::new();
        while !cd_slice.is_empty() {
            let cdr = cd.add_mut(cd_slice.clone(), |cdr_slice, cdr| {
                let (consumed, cdr) = consumed(&mut cd_slice, |b| decode_cdr(cdr.make_obj(), b))?;
                *cdr_slice = consumed;
                Ok(cdr)
            })?;
            cds.push(cdr);
        }
        Ok(cds)
    })?;

    let lf_slice = b.slice(..eocd.cd_range().start);
    let lf = root.add_mut("local_files", lf_slice.clone(), |_, lf| {
        let a = lf.make_arr();
        let offset = |cdr: &CentralDirRecord| {
            (cdr.disk_nr_start == eocd.disk_nr).then_some(cdr.local_file_offset)
        };
        for offset in cd.iter().filter_map(offset) {
            let offset: usize = offset.try_into().unwrap();
            a.add_mut(lf_slice.slice(offset..), |lfr_slice, lfr| {
                set_consumed(lfr_slice, |b| decode_local_file(lfr.make_obj(), b))
            })?;
        }

        Ok(())
    });

    Ok(())
}
