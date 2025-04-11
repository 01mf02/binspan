use bytes::Bytes;
use core::cell::LazyCell;
use core::fmt;
use core::ops::{Range, RangeBounds};
use std::rc::Rc;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct Error {
    position: Bytes,
    path: Vec<Index>,
    msg: String,
}

#[derive(Clone, Debug)]
pub enum Index {
    Str(&'static str),
    Int(usize),
}

impl Error {
    pub fn new(position: Bytes, msg: String) -> Self {
        Self {
            position,
            path: Vec::new(),
            msg,
        }
    }

    fn with_index(mut self, i: Index) -> Self {
        self.path.push(i);
        self
    }
}

pub type Decoded<T> = (Meta, Val, T);

/// Metadata of a value.
///
/// This is precisely the information that gets lost when changing a value.
#[derive(Clone, Debug)]
pub struct Meta {
    pub bytes: Bytes,
    error: Option<Error>,
    format: Option<fn(&Val) -> fmt::Result>,
    description: Option<String>,
}

impl Meta {
    pub fn describe(self, description: Option<String>) -> Self {
        Self {
            description,
            ..self
        }
    }
}

impl From<Bytes> for Meta {
    fn from(bytes: Bytes) -> Self {
        Self {
            bytes,
            error: None,
            format: None,
            description: None,
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
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Raw { gap: bool },
    Str(Bytes),
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
            Self::Raw { .. } | Self::Str(_) | Self::Bool(_) => self.clone(),
            Self::U8(_) | Self::U16(_) | Self::U32(_) | Self::U64(_) => self.clone(),
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

    pub fn add_consumed<T, F>(&mut self, field: &'static str, b: &mut Bytes, f: F) -> Result<T>
    where
        F: FnOnce(&mut Bytes, &mut Val) -> Result<T>,
    {
        self.add_mut(field, Meta::from(&*b), |m, v| consume(b, m, |b| f(b, v)))
    }

    pub fn add<T>(&mut self, field: &'static str, r: Result<Decoded<T>>) -> Result<T> {
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

    pub fn add_consumed<T, F>(&mut self, b: &mut Bytes, f: F) -> Result<T>
    where
        F: FnOnce(&mut Bytes, &mut Val) -> Result<T>,
    {
        self.add_mut(Meta::from(&*b), |m, v| consume(b, m, |b| f(b, v)))
    }
}

pub fn take(left: &mut Bytes, n: usize) -> Result<Bytes> {
    let right = try_split_off(left, n)?;
    Ok(core::mem::replace(left, right))
}

pub fn try_split_off(b: &mut Bytes, at: usize) -> Result<Bytes> {
    if at > b.len() {
        Err(Error::new(b.clone(), format!("expected {at} bytes")))
    } else {
        Ok(b.split_off(at))
    }
}

fn to_range(bounds: impl RangeBounds<usize>, len: usize) -> Result<Range<usize>, usize> {
    use core::ops::Bound;
    let begin = match bounds.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.checked_add(1).ok_or(n)?,
        Bound::Unbounded => 0,
    };
    let end = match bounds.end_bound() {
        Bound::Included(&n) => n.checked_add(1).ok_or(n)?,
        Bound::Excluded(&n) => n,
        Bound::Unbounded => len,
    };

    let max = core::cmp::max(begin, end);
    if max > len {
        Err(max)
    } else {
        Ok(begin..end)
    }
}

// Panics if `range.start > range.end`!
pub fn try_slice(b: &Bytes, range: impl RangeBounds<usize>) -> Result<Bytes> {
    let err = |n| Error::new(b.clone(), format!("expected {n} bytes"));
    Ok(b.slice(to_range(range, b.len()).map_err(err)?))
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
    to.bytes = consumed;
    Ok(y)
}

macro_rules! decode_int {
    ($width: expr, $f:ident, $ty:ident, $val:expr) => {
        pub fn $ty(b: &mut Bytes) -> Result<Decoded<$ty>> {
            let b = take(b, $width)?;
            // SAFETY: if `take` returns `Ok(b)`, then `b.len() = $width`
            let a: [u8; $width] = (*b).try_into().unwrap();
            let u = $ty::$f(a);
            Ok((Meta::from(b), $val(u), u))
        }
    };
}

pub mod le {
    use super::*;
    decode_int!(1, from_le_bytes, u8, Val::U8);
    decode_int!(2, from_le_bytes, u16, Val::U16);
    decode_int!(4, from_le_bytes, u32, Val::U32);
    decode_int!(8, from_le_bytes, u64, Val::U64);
}

pub fn raw(b: &mut Bytes, n: usize) -> Result<Decoded<Bytes>> {
    let b = take(b, n)?;
    Ok((Meta::from(&b), Val::default(), b))
}

pub fn precise(b: &mut Bytes, s: &[u8], force: bool) -> Result<Decoded<()>> {
    let byte_str = |b: &[u8]| b.iter().copied().map(char::from).collect::<String>();
    let err = || format!("expected byte sequence {:?}", byte_str(s));
    let b = take(b, s.len()).map_err(|e| Error { msg: err(), ..e })?;
    if b == s || force {
        Ok((Meta::from(b), Val::default(), ()))
    } else {
        Err(Error::new(b, err()))
    }
}
