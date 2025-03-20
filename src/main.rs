#[macro_use]
mod tar;
mod tar2;
mod zip;

fn main() -> std::io::Result<()> {
    /*
    use std::rc::Rc;
    let file: &[u8] = include_bytes!("../test.tar");
    let mut d = file;
    let tar = tar2::decode_tar(&mut d);
    for file in tar {
        use tar::AsVal;
        let file = file.unwrap();
        //dbg!(&file);
        //dbg!(file.as_val());
        dbg!(file.as_src_val());
        let src_val = tar::SrcVal::Dyn(&file);
        let json = tar::JsonVal::Src(Rc::new(src_val));
    }
    */

    let mut args = std::env::args();
    args.next();
    let filename = args.next().expect("pass ZIP filename as argument");
    let file = std::fs::File::open(filename)?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }?;

    let b = bytes::Bytes::from_owner(mmap);
    let mut o = zip::Obj::default();
    zip::decode_zip(&mut o, b).unwrap();
    //println!("{o:?}");
    Ok(())
}
