use bytes::Bytes;

const CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x01\x02";
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
struct CentralDirRecord {
    disk_nr_start: u16,
    local_file_offset: u32,
}

fn decode_cdr(o: &mut Obj, b: &mut Bytes) -> Result<CentralDirRecord> {
    o.add("signature", precise(b, CENTRAL_DIR_SIG))?;
    o.add("version_made_by", u16_le(b))?;
    o.add("version_needed", u16_le(b))?;
    o.add("flags", raw(b, 2))?;
    o.add("compression_method", u16_le(b))?;
    o.add("last_mod_file_time", u16_le(b))?;
    o.add("last_mod_file_date", u16_le(b))?;
    o.add("crc_32", u32_le(b))?;
    o.add("compressed_size", u32_le(b))?;
    o.add("uncompressed_size", u32_le(b))?;
    let filename_len = o.add("file_name_length", u16_le(b))?;
    let extra_field_len = o.add("extra_field_length", u16_le(b))?;
    let file_comment_len = o.add("file_comment_length", u16_le(b))?;
    let disk_nr_start = o.add("disk_number_where_file_starts", u16_le(b))?;
    o.add("internal_file_attributes", u16_le(b))?;
    o.add("external_file_attributes", u32_le(b))?;
    let local_file_offset = o.add("relative_offset_of_local_file_header", u32_le(b))?;
    o.add("file_name", raw(b, filename_len.into()))?;
    o.add("extra_fields", raw(b, extra_field_len.into()))?;
    o.add("file_comment", raw(b, file_comment_len.into()))?;

    Ok(CentralDirRecord {
        disk_nr_start,
        local_file_offset,
    })
}

fn find_eocds(b: &[u8]) -> Option<usize> {
    let is_eocds = |w| w == END_OF_CENTRAL_DIR_SIG;
    Some(b.len() - (b.windows(4).rev().take(128).position(is_eocds)? + 4))
}

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
                let cdr = decode_cdr(cdr.make_obj(), &mut cd_slice)?;
                cdr_slice.truncate(cdr_slice.len() - cd_slice.len());
                Ok(cdr)
            })?;
            cds.push(cdr);
        }
        Ok(cds)
    })?;

    Ok(())
}
