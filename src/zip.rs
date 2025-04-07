use crate::decode::*;
use bitflags::bitflags;
use bytes::Bytes;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x01\x02";
const LOCAL_FILE_SIG: &[u8; 4] = b"PK\x03\x04";
const END_OF_CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x05\x06";
const END_OF_CENTRAL_DIR_64_SIG: &[u8; 4] = b"PK\x06\x06";
const END_OF_CENTRAL_DIR_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";
const DATA_INDICATOR_SIG: &[u8; 4] = b"PK\x07\x08";

#[derive(Default)]
pub struct Opts {
    force: bool,
}

#[derive(Debug)]
struct EndOfCentralDirRecord {
    disk_nr: u32,
    size_cd: u64,
    offset_cd: u64,
}

impl EndOfCentralDirRecord {
    fn cd_range(&self) -> core::ops::Range<usize> {
        let cd_start: usize = self.offset_cd.try_into().unwrap();
        let cd_len: usize = self.size_cd.try_into().unwrap();
        cd_start..cd_start + cd_len
    }
}

// Maximal size for ZIP-32: 4*16+2*32 bits = 128 bits
fn decode_eocd_common(o: &mut Obj, b: &mut Bytes, zip64: bool) -> Result<EndOfCentralDirRecord> {
    let u16_as_u32 = |b: &mut Bytes| u16_le(b).map(|(m, v, u)| (m, v, u.into()));
    let u32_as_u64 = |b: &mut Bytes| u32_le(b).map(|(m, v, u)| (m, v, u.into()));
    let small = if zip64 { u32_le } else { u16_as_u32 };
    let large = if zip64 { u64_le } else { u32_as_u64 };

    let disk_nr = o.add("disk_nr", small(b))?;
    o.add("start_disk_nr", small(b))?;
    o.add("nr_of_central_dir_records_on_disk", small(b))?;
    o.add("nr_of_central_dir_records", small(b))?;
    let size_cd = o.add("size_of_central_dir", large(b))?;
    let offset_cd = o.add("offset_of_start_of_central_dir", large(b))?;
    Ok(EndOfCentralDirRecord {
        disk_nr,
        size_cd,
        offset_cd,
    })
}

// Maximal size: 32+128+16+(2^16 * 8) bits = 524464 bits = 65558 bytes
fn decode_eocd(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<EndOfCentralDirRecord> {
    o.add("signature", precise(b, END_OF_CENTRAL_DIR_SIG, opts.force))?;
    let eocdr = decode_eocd_common(o, b, false)?;
    let comment_length = o.add("comment_length", u16_le(b))?;
    o.add("comment", raw(b, comment_length.into()))?;
    Ok(eocdr)
}

fn decode_extensible_data(o: &mut Obj, b: &mut Bytes) -> Result {
    o.add("tag", u16_le(b))?;
    let data_size = o.add("size", u16_le(b))?;
    o.add("data", raw(b, data_size.into()))?;
    Ok(())
}

fn decode_eocd64(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<EndOfCentralDirRecord> {
    o.add(
        "signature",
        precise(b, END_OF_CENTRAL_DIR_64_SIG, opts.force),
    )?;
    let size_eocd = o.add("size_of_end_of_central_directory", u64_le(b))?;
    o.add("version_made_by", u16_le(b))?;
    o.add("version_needed", u16_le(b))?;
    let eocdr = decode_eocd_common(o, b, true)?;

    // number of bytes read by this function so far
    const FIXED_FIELD_SIZE: u64 = 44;
    let rest = size_eocd.checked_sub(FIXED_FIELD_SIZE);
    let mut b = take(b, rest.and_then(|l| l.try_into().ok()).unwrap())?;
    o.add_mut("extensible_data", Meta::from(&b), |_, ed| {
        let ed = ed.make_arr();
        while !b.is_empty() {
            ed.add_mut(Meta::from(&b), |edr_slice, edr| {
                consume(&mut b, edr_slice, |b| {
                    decode_extensible_data(edr.make_obj(), b)
                })
            })?;
        }
        Ok(())
    })?;

    Ok(eocdr)
}

// Total size: 32+32+64+32 bits = 160 bits = 20 bytes
fn decode_eocdl(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<u64> {
    o.add(
        "signature",
        precise(b, END_OF_CENTRAL_DIR_LOCATOR_SIG, opts.force),
    )?;
    o.add("disk_nr", u32_le(b))?;
    let offset_cdr = o.add("offset_of_end_of_central_dir_record", u64_le(b))?;
    o.add("total_disk_nr", u32_le(b))?;
    Ok(offset_cdr)
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
    struct Flags: u16 {
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

macro_rules! flags_obj {
    ($meta:ident, $flags:ident, $ty: ident) => {{
        let has = |name| $flags.contains($ty::from_name(name).unwrap());
        let f = |(name, _)| (name, $meta.clone(), Val::Bool(has(name)));
        Val::Obj(Obj($ty::all().iter_names().map(f).collect()))
    }};
}

macro_rules! lazy_flags {
    ($input: expr, $ty: ident) => {{
        let (m, _v, u) = $input;
        let flags = $ty::from_bits_retain(u);
        let (m_, flags_) = (m.clone(), flags.clone());
        (m, Val::lazy(move || flags_obj!(m_, flags_, $ty)), flags)
    }};
}

// https://stackoverflow.com/a/8012148
fn mask(u: u16, offset: u8, width: u8) -> u8 {
    let mask = ((1 << width as u16) - 1) << offset;
    ((u & mask) >> offset) as u8
}

// https://learn.microsoft.com/en-gb/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
fn sec_min_hr(time: u16) -> (u8, u8, u8) {
    (mask(time, 0, 5), mask(time, 5, 6), mask(time, 11, 5))
}

fn day_month_year(date: u16) -> (u8, u8, u8) {
    (mask(date, 0, 5), mask(date, 5, 4), mask(date, 9, 7))
}

fn decode_td<F>(b: &mut Bytes, f: F) -> Result<(Meta, Val, u16)>
where
    F: FnOnce(u16) -> [(&'static str, Val); 3],
{
    let (meta, _, time) = u16_le(b)?;
    let span = meta.bytes.clone();
    let entries = f(time);
    let entry = move |(k, v)| (k, Meta::from(span.clone()), v);
    let val = move || Val::Obj(Obj(entries.into_iter().map(entry).collect()));
    Ok((meta, Val::lazy(val), time))
}

fn decode_time_date(o: &mut Obj, b: &mut Bytes) -> Result {
    let time = decode_td(b, |time| {
        let (sec, min, hr) = sec_min_hr(time);
        let (sec, min, hr) = (Val::U8(sec * 2), Val::U8(min), Val::U8(hr));
        [("second", sec), ("minute", min), ("hour", hr)]
    });
    let date = decode_td(b, |date| {
        let (day, mon, yr) = day_month_year(date);
        let (day, mon, yr) = (Val::U8(day), Val::U8(mon), Val::U16(yr as u16 + 1980));
        [("day", day), ("month", mon), ("year", yr)]
    });
    o.add("fat_time", time)?;
    o.add("fat_date", date)?;
    Ok(())
}

bitflags! {
    #[derive(Clone, Debug)]
    struct Timestamp: u8 {
        const modification_time_present = 1 << 0;
        const access_time_present = 1 << 1;
        const creation_time_present = 1 << 2;
        // 5 unused fields

        // the source may set any bits
        const _ = !0;
    }
}

fn decode_extended_timestamp(o: &mut Obj, b: &mut Bytes) -> Result<()> {
    let flags = o.add("flags", Ok(lazy_flags!(le::u8(b)?, Timestamp)))?;
    let times = [
        ("modification_time", Timestamp::modification_time_present),
        ("access_time", Timestamp::access_time_present),
        ("creation_time", Timestamp::creation_time_present),
    ];
    for (key, flag) in times {
        if flags.contains(flag) && !b.is_empty() {
            o.add(key, le::u32(b))?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Zip64 {
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    local_file_offset: Option<u64>,
    disk_nr_start: Option<u32>,
}

fn decode_zip64(o: &mut Obj, b: &mut Bytes) -> Result<Zip64> {
    let mut zip64 = Zip64::default();
    if !b.is_empty() {
        zip64.uncompressed_size = Some(o.add("uncompressed_size", u64_le(b))?);
    }
    if !b.is_empty() {
        zip64.compressed_size = Some(o.add("compressed_size", u64_le(b))?);
    }
    if !b.is_empty() {
        zip64.local_file_offset = Some(o.add("local_file_offset", u64_le(b))?);
    }
    if !b.is_empty() {
        zip64.disk_nr_start = Some(o.add("disk_nr_start", u32_le(b))?);
    }
    Ok(zip64)
}

fn decode_common(o: &mut Obj, b: &mut Bytes) -> Result<Common> {
    let flags = o.add("flags", Ok(lazy_flags!(u16_le(b)?, Flags)))?;
    let compression_method = o.add("compression_method", u16_le(b))?;
    o.add_mut("last_modification", Meta::from(&*b), |lm_meta, lm| {
        consume(b, lm_meta, |b| decode_time_date(lm.make_obj(), b))
    })?;
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
    disk_nr_start: u32,
    local_file_offset: u64,
}

fn decode_name_and_fields(o: &mut Obj, b: &mut Bytes, common: &Common) -> Result<Zip64> {
    o.add("file_name", raw(b, common.filename_len.into()))?;
    let efs_slice = take(b, common.extra_field_len.into())?;
    o.add_mut("extra_fields", Meta::from(&efs_slice), |_, efs| {
        decode_extra_fields(efs.make_arr(), efs_slice)
    })
}

fn decode_cdr(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<CentralDirRecord> {
    o.add("signature", precise(b, CENTRAL_DIR_SIG, opts.force))?;
    o.add("version_made_by", u16_le(b))?;
    o.add("version_needed", u16_le(b))?;
    let common = decode_common(o, b)?;

    let file_comment_len = o.add("file_comment_length", u16_le(b))?;
    let disk_nr_start = o.add("disk_number_where_file_starts", u16_le(b))?;
    o.add("internal_file_attributes", u16_le(b))?;
    o.add("external_file_attributes", u32_le(b))?;
    let local_file_offset = o.add("relative_offset_of_local_file_header", u32_le(b))?;

    let zip64 = decode_name_and_fields(o, b, &common)?;
    o.add("file_comment", raw(b, file_comment_len.into()))?;

    Ok(CentralDirRecord {
        common,
        disk_nr_start: zip64.disk_nr_start.unwrap_or(disk_nr_start.into()),
        local_file_offset: zip64.local_file_offset.unwrap_or(local_file_offset.into()),
    })
}

fn uncompress(b: Bytes, method: CompressionMethod) -> Val {
    use miniz_oxide::inflate::decompress_to_vec;
    Val::Obj(Obj(match method {
        CompressionMethod::deflated => decompress_to_vec(&b).ok().map(Bytes::from),
        CompressionMethod::none => Some(b.clone()),
        _ => None,
    }
    .into_iter()
    .map(|uc| ("uncompressed", Meta::from(uc), Val::default()))
    .collect()))
}

fn decode_extra_field(o: &mut Obj, b: &mut Bytes) -> Result<Option<Zip64>> {
    let tag = o.add("tag", u16_le(b))?;
    let size = o.add("size", u16_le(b))?;
    let (meta, v, mut b) = raw(b, size.into())?;
    o.add_mut("data", meta, |_, d| match tag {
        0x001 => decode_zip64(d.make_obj(), &mut b).map(Some),
        0x5455 => decode_extended_timestamp(d.make_obj(), &mut b).map(|_| None),
        _ => {
            *d = v;
            Ok(None)
        }
    })
}

fn decode_extra_fields(a: &mut Arr, mut b: Bytes) -> Result<Zip64> {
    let mut zip64 = Zip64::default();
    while !b.is_empty() {
        let y = a.add_mut(Meta::from(&b), |ef_meta, ef| {
            consume(&mut b, ef_meta, |b| decode_extra_field(ef.make_obj(), b))
        })?;
        zip64 = y.unwrap_or(zip64);
    }
    Ok(zip64)
}

fn decode_data_indicator(o: &mut Obj, b: &mut Bytes) -> Result<()> {
    if b.starts_with(DATA_INDICATOR_SIG) {
        o.add("signature", precise(b, DATA_INDICATOR_SIG, true))?;
    }
    o.add("crc32_uncompressed", u32_le(b))?;
    o.add("compressed_size", u32_le(b))?;
    o.add("uncompressed_size", u32_le(b))?;
    Ok(())
}

fn decode_local_file(o: &mut Obj, b: &mut Bytes, opts: &Opts, cdr_common: &Common) -> Result<()> {
    o.add("signature", precise(b, LOCAL_FILE_SIG, opts.force))?;
    o.add("version_needed", u16_le(b))?;
    let lf_common = decode_common(o, b)?;
    let zip64 = decode_name_and_fields(o, b, &lf_common)?;
    // no file_comment here (unlike in central directory)

    let compressed_size = match zip64
        .compressed_size
        .unwrap_or(lf_common.compressed_size.into())
    {
        0 => cdr_common.compressed_size.into(),
        s => s,
    };
    let compressed_size = compressed_size.try_into().unwrap();

    if compressed_size > 0 {
        let (compressed_meta, _v, compressed) = raw(b, compressed_size)?;
        let method = CompressionMethod::from_u16(lf_common.compression_method);
        let f = |method| Val::lazy(move || uncompress(compressed.clone(), method));
        let entry = (compressed_meta, method.map_or(Val::default(), f), ());
        o.add("compressed", Ok(entry))?;
    }

    if lf_common.flags.contains(Flags::data_descriptor) {
        o.add_mut("data_indicator", Meta::from(&*b), |dd_meta, dd| {
            consume(b, dd_meta, |b| decode_data_indicator(dd.make_obj(), b))
        })?;
    }
    Ok(())
}

fn find(b: &[u8], sig: &[u8; 4], len: usize) -> Option<usize> {
    Some(b.len() - (b.windows(4).rev().take(len - 3).position(|w| w == sig)? + 4))
}

fn decode_eocds(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<EndOfCentralDirRecord> {
    let eocds_abs = find(&b, END_OF_CENTRAL_DIR_SIG, 65558).unwrap();
    let mut eocd_slice = b.split_off(eocds_abs);
    let eocd_meta = Meta::from(&eocd_slice);
    let eocd = o.add_mut("end_of_central_dir_record", eocd_meta, |_, eocd| {
        decode_eocd(eocd.make_obj(), &mut eocd_slice, &opts)
    })?;

    if let Some(eocdl_abs) = find(&b, END_OF_CENTRAL_DIR_LOCATOR_SIG, 20) {
        let mut eocdl_slice = b.split_off(eocdl_abs);
        let eocdl_meta = Meta::from(&eocdl_slice);
        let offset_eocd = o.add_mut(
            "end_of_central_directory_locator",
            eocdl_meta,
            |_, eocdl| decode_eocdl(eocdl.make_obj(), &mut eocdl_slice, opts),
        )?;
        let offset_eocd: usize = offset_eocd.try_into().unwrap();

        let mut eocd_slice = try_slice(&b, offset_eocd..)?;
        let eocd_meta = Meta::from(&eocd_slice);
        o.add_mut(
            "end_of_central_directory_record_zip64",
            eocd_meta,
            |_, eocd| decode_eocd64(eocd.make_obj(), &mut eocd_slice, opts),
        )
    } else {
        Ok(eocd)
    }
}

pub fn decode_zip(root: &mut Obj, mut b: Bytes, opts: &Opts) -> Result<()> {
    let eocd = decode_eocds(root, &mut b, opts)?;

    let mut cd_slice = try_slice(&b, eocd.cd_range())?;
    let cd = root.add_mut("central_directories", Meta::from(&cd_slice), |_, cd| {
        let cd = cd.make_arr();
        let mut cds = Vec::new();
        while !cd_slice.is_empty() {
            let cdr = cd.add_mut(Meta::from(&cd_slice), |cdr_slice, cdr| {
                consume(&mut cd_slice, cdr_slice, |b| {
                    decode_cdr(cdr.make_obj(), b, &opts)
                })
            })?;
            cds.push(cdr);
        }
        Ok(cds)
    })?;

    let lf_slice = try_slice(&b, ..eocd.cd_range().start)?;
    root.add_mut("local_files", Meta::from(&lf_slice), |_, lf| {
        let a = lf.make_arr();
        for cdr in cd.iter().filter(|cdr| cdr.disk_nr_start == eocd.disk_nr) {
            let offset: usize = cdr.local_file_offset.try_into().unwrap();
            let mut lfr_slice = lf_slice.slice(offset..);
            a.add_mut(Meta::from(&lfr_slice), |lfr_meta, lfr| {
                consume(&mut lfr_slice, lfr_meta, |b| {
                    decode_local_file(lfr.make_obj(), b, &opts, &cdr.common)
                })
            })?;
        }
        Ok(())
    })?;

    Ok(())
}
