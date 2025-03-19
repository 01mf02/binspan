use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;

pub type U8<'a> = (&'a str, u8);
pub type U16<'a> = (&'a str, u16);
pub type U32<'a> = (&'a str, u32);
pub type U64<'a> = (&'a str, u64);

#[derive(Debug)]
pub enum JsonVal<'a> {
    Str(String),
    Arr(Vec<Self>),
    Obj(HashMap<String, Self>),
    Int(isize),
    Src(Rc<SrcVal<'a>>),
}

impl<'a> JsonVal<'a> {
    fn expand(&self) -> Self {
        match self {
            Self::Src(s) => Self::from(&**s),
            _ => todo!(),
        }
    }
}

impl<'a> From<&SrcVal<'a>> for JsonVal<'a> {
    fn from(v: &SrcVal<'a>) -> Self {
        match v {
            SrcVal::Dyn(v) => {
                let (src, v) = v.as_src_val();
                let v = SrcVal::Val(src, v);
                Self::from(&v)
            }
            SrcVal::Val(src, v) => match v {
                Val::Raw => JsonVal::Str(match src {
                    Src::Str(s) => s.to_string(),
                    Src::Bytes(b) => b.iter().copied().map(char::from).collect(),
                }),
                Val::Arr(a) => JsonVal::Arr(a.iter().map(Self::from).collect()),
                Val::Obj(o) => JsonVal::Obj(
                    o.iter()
                        .map(|(k, v)| ((*k).into(), Self::from(v)))
                        .collect(),
                ),
                Val::Int(i) => JsonVal::Int(*i),
            },
        }
    }
}

#[derive(Debug)]
pub enum SrcVal<'a> {
    Dyn(&'a dyn AsVal<'a>),
    Val(Src<'a>, Val<'a>),
}

#[derive(Debug)]
pub enum Src<'a> {
    Str(&'a str),
    Bytes(&'a [u8]),
}

#[derive(Debug)]
pub enum Val<'a> {
    Arr(Vec<SrcVal<'a>>),
    Obj(Vec<(&'static str, SrcVal<'a>)>),
    Int(isize),
    // either string or bytes, depending on the `Src` corresponding to the `Val`
    Raw,
}

pub trait AsVal<'a>: Debug {
    fn as_src_val(&self) -> (Src<'a>, Val<'a>);
}

pub fn take<'a>(d: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if n > d.len() {
        None
    } else {
        let d_ = &d[..n];
        *d = &d[n..];
        Some(d_)
    }
}

#[macro_export]
macro_rules! str_raw {
    ($self: ident, $i: ident) => {
        (stringify!($i), SrcVal::Val(Src::Str($self.$i), Val::Raw))
    };
}

#[macro_export]
macro_rules! bytes_raw {
    ($self: ident, $i: ident) => {
        (stringify!($i), SrcVal::Val(Src::Bytes($self.$i), Val::Raw))
    };
}

#[macro_export]
macro_rules! str_int {
    ($self: ident, $i: ident) => {{
        let int = Val::Int($self.$i.1.try_into().unwrap());
        (stringify!($i), SrcVal::Val(Src::Str($self.$i.0), int))
    }};
}

#[macro_export]
macro_rules! bytes_int {
    ($self: ident, $i: ident) => {{
        let int = Val::Int($self.$i.1.try_into().unwrap());
        (stringify!($i), SrcVal::Val(Src::Bytes($self.$i.0), int))
    }};
}
