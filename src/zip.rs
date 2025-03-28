use crate::decode::*;
use bitflags::bitflags;
use bytes::Bytes;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x01\x02";
const LOCAL_FILE_SIG: &[u8; 4] = b"PK\x03\x04";
const END_OF_CENTRAL_DIR_SIG: &[u8; 4] = b"PK\x05\x06";

#[derive(Default)]
pub struct Opts {
    force: bool,
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

fn decode_eocd(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<EndOfCentralDirRecord> {
    o.add("signature", precise(b, END_OF_CENTRAL_DIR_SIG, opts.force))?;
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

fn flags_obj(m: Meta, flags: Flags) -> Val {
    let has = |name| flags.contains(Flags::from_name(name).unwrap());
    let f = |(name, _)| (name, m.clone(), Val::Bool(has(name)));
    Val::Obj(Obj(Flags::all().iter_names().map(f).collect()))
}

fn decode_flags(b: &mut Bytes) -> Result<(Meta, Val, Flags)> {
    let (m, _v, u) = u16_le(b)?;
    let flags = Flags::from_bits_retain(u);
    let (m_, flags_) = (m.clone(), flags.clone());
    Ok((m, Val::lazy(move || flags_obj(m_, flags_)), flags))
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

fn decode_cdr(o: &mut Obj, b: &mut Bytes, opts: &Opts) -> Result<CentralDirRecord> {
    o.add("signature", precise(b, CENTRAL_DIR_SIG, opts.force))?;
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

fn decode_extra_field(o: &mut Obj, b: &mut Bytes) -> Result<()> {
    o.add("tag", u16_le(b))?;
    let size = o.add("size", u16_le(b))?;
    o.add("data", raw(b, size.into()))?;
    Ok(())
}

fn decode_extra_fields(a: &mut Arr, mut b: Bytes) -> Result<()> {
    while !b.is_empty() {
        a.add_mut(Meta::from(&b), |ef_meta, ef| {
            consume(&mut b, ef_meta, |b| decode_extra_field(ef.make_obj(), b))
        })?;
    }
    Ok(())
}

fn decode_local_file(o: &mut Obj, b: &mut Bytes, opts: &Opts, cdr_common: &Common) -> Result<()> {
    o.add("signature", precise(b, LOCAL_FILE_SIG, opts.force))?;
    let lf_common = decode_common(o, b)?;

    o.add("file_name", raw(b, lf_common.filename_len.into()))?;
    let efs_slice = take(b, lf_common.extra_field_len.into())?;
    o.add_mut("extra_fields", Meta::from(&efs_slice), |_, efs| {
        decode_extra_fields(efs.make_arr(), efs_slice)
    })?;
    // no file_comment here (unlike in central directory)

    let compressed_size = match lf_common.compressed_size {
        0 => cdr_common.compressed_size,
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

    // TODO: read data descriptor
    Ok(())
}

fn find_eocds(b: &[u8]) -> Option<usize> {
    let is_eocds = |w| w == END_OF_CENTRAL_DIR_SIG;
    Some(b.len() - (b.windows(4).rev().take(128).position(is_eocds)? + 4))
}

// TODO: slice() may panic!
pub fn decode_zip(root: &mut Obj, b: Bytes, opts: &Opts) -> Result<()> {
    let eocds_abs = find_eocds(&b).unwrap();
    let eocd_slice = b.slice(eocds_abs..);
    let eocd_meta = Meta::from(&eocd_slice);
    let eocd = root.add_mut("end_of_central_dir_record", eocd_meta, |_, eocd| {
        decode_eocd(eocd.make_obj(), &mut eocd_slice.clone(), &opts)
    })?;

    let mut cd_slice = b.slice(eocd.cd_range());
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

    let lf_slice = b.slice(..eocd.cd_range().start);
    root.add_mut("local_files", Meta::from(&lf_slice), |_, lf| {
        let a = lf.make_arr();
        for cdr in cd.iter().filter(|cdr| cdr.disk_nr_start == eocd.disk_nr) {
            let offset: usize = cdr.local_file_offset.try_into().unwrap();
            let lfr_slice = lf_slice.slice(offset..);
            a.add_mut(Meta::from(&lfr_slice), |lfr_meta, lfr| {
                consume(&mut lfr_slice.clone(), lfr_meta, |b| {
                    decode_local_file(lfr.make_obj(), b, &opts, &cdr.common)
                })
            })?;
        }
        Ok(())
    })?;

    Ok(())
}
