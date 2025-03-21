use bitflags::bitflags;
use bytes::Bytes;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::rc::Rc;

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

#[derive(Clone, Debug, Default)]
pub struct Obj(Vec<(&'static str, Bytes, Val)>);

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug)]
pub enum Atom {
    Bool(bool),
    U16(u16),
    U32(u32),
    Str(String),
    Raw,
}

#[derive(Clone, Debug)]
pub enum Val {
    Atom(Atom, Option<Rc<dyn Eval>>),
    Many(Many),
}

#[derive(Clone, Debug)]
pub enum Many {
    Arr(Arr),
    Obj(Obj),
}

pub trait Eval: std::fmt::Debug {
    fn eval(&self) -> Result<Many>;
}

impl Eval for Many {
    fn eval(&self) -> Result<Many> {
        Ok(self.clone())
    }
}

impl Default for Val {
    fn default() -> Self {
        Atom::Raw.into()
    }
}

impl Obj {
    pub fn unfold(self) -> Result<Self> {
        let f = |(k, b, v): (&'static str, Bytes, Val)| Ok((k, b, v.unfold()?));
        self.0.into_iter().map(f).collect::<Result<_>>().map(Self)
    }
}

impl Arr {
    pub fn unfold(self) -> Result<Self> {
        let f = |(b, v): (Bytes, Val)| Ok((b, v.unfold()?));
        self.0.into_iter().map(f).collect::<Result<_>>().map(Self)
    }
}

impl Many {
    fn unfold(self) -> Result<Self> {
        match self {
            Self::Arr(a) => a.unfold().map(Self::Arr),
            Self::Obj(o) => o.unfold().map(Self::Obj),
        }
    }
}

impl Val {
    fn unfold(self) -> Result<Self> {
        let f = |l: Rc<dyn Eval>| Ok(Rc::new(l.eval()?.unfold()?) as Rc<dyn Eval>);
        match self {
            Self::Atom(a, l) => Ok(Self::Atom(a, l.map(f).transpose()?)),
            Self::Many(m) => m.unfold().map(Self::Many),
        }
    }

    fn make_arr(&mut self) -> &mut Arr {
        *self = Val::Many(Many::Arr(Arr::default()));
        match self {
            Val::Many(Many::Arr(a)) => a,
            _ => panic!(),
        }
    }

    fn make_obj(&mut self) -> &mut Obj {
        *self = Val::Many(Many::Obj(Obj::default()));
        match self {
            Val::Many(Many::Obj(o)) => o,
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

#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive)]
enum CompressionMethod {
    none = 0,
    shrunk = 1,
    reduced_compression_factor1 = 2,
    reduced_compression_factor2 = 3,
    reduced_compression_factor3 = 4,
    reduced_compression_factor4 = 5,
    imploded = 6,
    deflated = 8,
    enhanced_deflated = 9,
    pk_ware_dcl_imploded = 10,
    bzip2 = 12,
    lzma = 14,
    ibmterse = 18,
    ibmlz77z = 19,
    pp_md = 98,
}

#[derive(Debug)]
struct FlagsObj(Bytes, Flags);

impl Eval for FlagsObj {
    fn eval(&self) -> Result<Many> {
        let has = |name| self.1.contains(Flags::from_name(name).unwrap());
        let f = |(name, _)| (name, self.0.clone(), Atom::Bool(has(name)).into());
        let o = Obj(Flags::all().iter_names().map(f).collect());
        Ok(Many::Obj(o))
    }
}

fn decode_flags(b: &mut Bytes) -> Result<(Bytes, Val, Flags)> {
    let (b, _v, u) = u16_le(b)?;
    let flags = Flags::from_bits_retain(u);
    let poly = Rc::new(FlagsObj(b.clone(), flags.clone()));
    Ok((b, Val::Atom(Atom::U16(u), Some(poly)), flags))
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
struct Uncompress(CompressionMethod, Bytes);

impl Eval for Uncompress {
    fn eval(&self) -> Result<Many> {
        Ok(Many::Obj(Obj(match self.0 {
            CompressionMethod::deflated => {
                use miniz_oxide::inflate::decompress_to_vec;
                decompress_to_vec(&self.1).ok().map(Bytes::from)
            }
            CompressionMethod::none => Some(self.1.clone()),
            _ => None,
        }
        .into_iter()
        .map(|uc| ("uncompressed", uc, Atom::Raw.into()))
        .collect())))
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
        let (compressed, _v, ()) = raw(b, compressed_size)?;
        let method = CompressionMethod::from_u16(lf_common.compression_method);
        let uncompressed =
            method.map(|method| Rc::new(Uncompress(method, compressed.clone())) as Rc<dyn Eval>);
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
    root.add_mut("local_files", lf_slice.clone(), |_, lf| {
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
    })?;

    Ok(())
}
