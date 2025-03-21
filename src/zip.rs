use bitflags::bitflags;
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
    Atom(Atom, Option<Box<Val>>),
    Lazy(Box<dyn Eval>),
}

impl Default for Val {
    fn default() -> Self {
        Atom::Raw.into()
    }
}

impl Val {
    pub fn unfold(self) -> Self {
        match self {
            Self::Arr(a) => Self::Arr(Arr(a.0.into_iter().map(|(b, v)| (b, v.unfold())).collect())),
            Self::Obj(o) => Self::Obj(Obj(o
                .0
                .into_iter()
                .map(|(n, b, v)| (n, b, v.unfold()))
                .collect())),
            Self::Atom(a, v) => Self::Atom(a, v.map(|v| Box::new(v.unfold()))),
            Self::Lazy(l) => todo!(), //l.eval().unfold(),
        }
    }

    fn lazy(l: impl Eval + 'static) -> Self {
        Self::Lazy(Box::new(l))
    }

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
        Self::Atom(a, None)
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
    flags: Flags,
    compression_method: u16,
    compressed_size: u32,
    filename_len: u16,
    extra_field_len: u16,
}

bitflags! {
    #[derive(Clone, Debug)]
    pub struct Flags: u16 {
        const encrypted = 1 << 0;
        const compression1 = 1 << 1;
        const compression0 = 1 << 2;
        const data_descriptor = 1 << 3;
        const enhanced_deflation = 1 << 4;
        const compressed_patched_data = 1 << 5;
        const strong_encryption = 1 << 6;
        // 1 unused field

        // 3 unused fields
        const language_encoding = 1 << 11;
        // 1 reserved field
        const mask_header_values = 1 << 13;
        // 2 reserved fields

        // the source may set any bits
        const _ = !0;
    }
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

trait Eval: std::fmt::Debug {
    fn eval(&self) -> Result<(Bytes, Val)>;
}

#[derive(Debug)]
struct FlagsObj(Bytes, Flags);

impl Eval for FlagsObj {
    fn eval(&self) -> Result<(Bytes, Val)> {
        let has = |name| self.1.contains(Flags::from_name(name).unwrap());
        let f = |(name, _)| (name, self.0.clone(), Atom::Bool(has(name)).into());
        let o = Obj(Flags::all().iter_names().map(f).collect());
        Ok((self.0.clone(), Val::Obj(o)))
    }
}

fn decode_flags(b: &mut Bytes) -> Result<(Bytes, Val, Flags)> {
    let (b, _v, u) = u16_le(b)?;
    let flags = Flags::from_bits_retain(u);
    let v = Val::Atom(
        Atom::U16(u),
        Some(Val::lazy(FlagsObj(b.clone(), flags.clone())).into()),
    );
    Ok((b, v, flags))
}

fn decode_common(o: &mut Obj, b: &mut Bytes) -> Result<Common> {
    o.add("version_needed", u16_le(b))?;
    let flags = o.add("flags", decode_flags(b))?;
    let compression_method = o.add("compression_method", u16_le(b))?;
    o.add("last_modification_time", u16_le(b))?;
    o.add("last_modification_date", u16_le(b))?;
    o.add("crc_32", u32_le(b))?;
    let compressed_size = o.add("compressed_size", u32_le(b))?;
    o.add("uncompressed_size", u32_le(b))?;
    let filename_len = o.add("file_name_length", u16_le(b))?;
    let extra_field_len = o.add("extra_field_length", u16_le(b))?;
    Ok(Common {
        flags,
        compression_method,
        compressed_size,
        filename_len,
        extra_field_len,
    })
}

#[derive(Debug)]
struct CentralDirRecord {
    common: Common,
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
        common,
        disk_nr_start,
        local_file_offset,
    })
}

#[derive(Debug)]
struct Uncompress(Bytes);

impl Eval for Uncompress {
    fn eval(&self) -> Result<(Bytes, Val)> {
        use miniz_oxide::inflate::decompress_to_vec;
        let b = decompress_to_vec(&self.0).ok().map(Bytes::from).unwrap();
        Ok((b, Atom::Raw.into()))
    }
}

fn decode_local_file(o: &mut Obj, b: &mut Bytes, cdr_common: &Common) -> Result<()> {
    o.add("signature", precise(b, LOCAL_FILE_SIG))?;
    let lf_common = decode_common(o, b)?;

    o.add("file_name", raw(b, lf_common.filename_len.into()))?;
    o.add("extra_fields", raw(b, lf_common.extra_field_len.into()))?;
    // no file_comment here (unlike in central directory)

    let compressed_size = match lf_common.compressed_size {
        0 => cdr_common.compressed_size,
        s => s,
    };
    let compressed_size = compressed_size.try_into().unwrap();

    if compressed_size > 0 {
        let (compressed, v, ()) = raw(b, compressed_size)?;

        let uncompressed = match CompressionMethod::from_u16(lf_common.compression_method) {
            Some(CompressionMethod::Deflated) => Some(Val::lazy(Uncompress(compressed.clone()))),
            Some(CompressionMethod::None) => Some(Atom::Raw.into()),
            _ => None,
        }
        .map(|uc| {
            let entry = ("uncompressed", compressed.clone(), uc);
            Box::new(Val::Obj(Obj(vec![entry])))
        });

        let entry = (compressed, Val::Atom(Atom::Raw, uncompressed), ());
        o.add("compressed", Ok(entry))?;
    }

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
        for cdr in cd.iter().filter(|cdr| cdr.disk_nr_start == eocd.disk_nr) {
            let offset: usize = cdr.local_file_offset.try_into().unwrap();
            a.add_mut(lf_slice.slice(offset..), |lfr_slice, lfr| {
                set_consumed(lfr_slice, |b| {
                    decode_local_file(lfr.make_obj(), b, &cdr.common)
                })
            })?;
        }

        Ok(())
    });

    Ok(())
}
