use bytes::Bytes;
use core::cell::LazyCell;
use std::rc::Rc;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct Error {
    position: Bytes,
    path: Vec<Index>,
    expect_len: usize,
    expect_typ: Expect,
}

#[derive(Clone, Debug)]
pub enum Index {
    Str(&'static str),
    Int(usize),
}

#[derive(Clone, Debug)]
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

/// Metadata of a value.
///
/// This is precisely the information that gets lost when changing a value.
#[derive(Clone, Debug)]
pub struct Meta {
    bytes: Bytes,
    description: Option<&'static str>,
    error: Option<Error>,
}

impl From<Bytes> for Meta {
    fn from(bytes: Bytes) -> Self {
        Self {
            bytes,
            description: None,
            error: None,
        }
    }
}

impl From<&Bytes> for Meta {
    fn from(bytes: &Bytes) -> Self {
        Self::from(bytes.clone())
    }
}

#[derive(Clone, Debug)]
pub enum Val {
    Bool(bool),
    U16(u16),
    U32(u32),
    Raw { gap: bool },
    Arr(Arr),
    Obj(Obj),
    Lazy(Rc<LazyCell<Val, Box<dyn FnOnce() -> Val>>>),
}

#[derive(Clone, Debug, Default)]
pub struct Obj(pub Vec<(&'static str, Meta, Val)>);

#[derive(Clone, Debug, Default)]
pub struct Arr(pub Vec<(Meta, Val)>);

impl Val {
    pub fn eval(&self) -> Self {
        let fo = |(k, m, v): &(_, Meta, Val)| (*k, m.clone(), v.eval());
        let fa = |(m, v): &(Meta, Val)| (m.clone(), v.eval());
        match self {
            Self::Lazy(l) => LazyCell::force(l).eval(),
            Self::Arr(Arr(a)) => Self::Arr(Arr(a.iter().map(fa).collect())),
            Self::Obj(Obj(o)) => Self::Obj(Obj(o.iter().map(fo).collect())),
            Self::Raw { .. } | Self::Bool(_) | Self::U16(_) | Self::U32(_) => self.clone(),
        }
    }

    pub fn make_arr(&mut self) -> &mut Arr {
        *self = Val::Arr(Arr::default());
        match self {
            Val::Arr(a) => a,
            _ => unreachable!(),
        }
    }

    pub fn make_obj(&mut self) -> &mut Obj {
        *self = Val::Obj(Obj::default());
        match self {
            Val::Obj(o) => o,
            _ => unreachable!(),
        }
    }

    pub fn lazy(f: impl FnOnce() -> Self + 'static) -> Self {
        Self::Lazy(Rc::new(LazyCell::new(Box::new(f))))
    }
}

impl Default for Val {
    fn default() -> Self {
        Self::Raw { gap: false }
    }
}

impl Obj {
    pub fn add_mut<T, F>(&mut self, field: &'static str, m: Meta, f: F) -> Result<T>
    where
        F: FnOnce(&mut Meta, &mut Val) -> Result<T>,
    {
        self.0.push((field, m, Val::default()));
        match self.0.last_mut() {
            Some((_, m, v)) => f(m, v).map_err(|e| {
                m.error = Some(e.clone());
                e.with_index(Index::Str(field))
            }),
            _ => unreachable!(),
        }
    }

    pub fn add<T>(&mut self, field: &'static str, r: Result<(Meta, Val, T)>) -> Result<T> {
        let (m, v, y) = r.map_err(|e| e.with_index(Index::Str(field)))?;
        self.0.push((field, m, v));
        Ok(y)
    }
}

impl Arr {
    pub fn add_mut<T, F>(&mut self, m: Meta, f: F) -> Result<T>
    where
        F: FnOnce(&mut Meta, &mut Val) -> Result<T>,
    {
        let i = self.0.len();
        self.0.push((m, Val::default()));
        match self.0.last_mut() {
            Some((m, v)) => f(m, v).map_err(|e| {
                m.error = Some(e.clone());
                e.with_index(Index::Int(i))
            }),
            _ => unreachable!(),
        }
    }
}

pub fn take(b: &mut Bytes, n: usize) -> Result<Bytes> {
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

pub fn consume<T>(
    b: &mut Bytes,
    to: &mut Meta,
    f: impl FnOnce(&mut Bytes) -> Result<T>,
) -> Result<T> {
    let (consumed, y) = consumed(b, f)?;
    *to = Meta::from(consumed);
    Ok(y)
}

pub fn u16_le(b: &mut Bytes) -> Result<(Meta, Val, u16)> {
    let b = take(b, 2).map_err(|e| e.with_typ(Expect::Int))?;
    let u = u16::from_le_bytes((*b).try_into().unwrap());
    Ok((Meta::from(b), Val::U16(u), u))
}

pub fn u32_le(b: &mut Bytes) -> Result<(Meta, Val, u32)> {
    let b = take(b, 4).map_err(|e| e.with_typ(Expect::Int))?;
    let u = u32::from_le_bytes((*b).try_into().unwrap());
    Ok((Meta::from(b), Val::U32(u), u))
}

pub fn raw(b: &mut Bytes, n: usize) -> Result<(Meta, Val, Bytes)> {
    let b = take(b, n)?;
    Ok((Meta::from(&b), Val::default(), b))
}

pub fn precise(b: &mut Bytes, s: &'static [u8], force: bool) -> Result<(Meta, Val, ())> {
    let err = move |e: Error| e.with_typ(Expect::Raw(s));
    let b = take(b, s.len()).map_err(err)?;
    if b == s || force {
        Ok((Meta::from(b), Val::default(), ()))
    } else {
        Err(err(Error::new(b, s.len())))
    }
}
