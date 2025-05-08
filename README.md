This is a framework for decoding binary data. Its goals are:

- Source information: Decoded data should store where it was derived from, up to the bit level.
- Exhaustiveness: Every part of an input file should be accessible in the decoded data.
- Redundant data: Decoded data should be able to provide functions to derive redundant information.
  For example, a ZIP file decoder could provide a function that calculates
  decompressed data from compressed data.
- Error handling: Decoding corrupted files should return information about uncorrupted parts.
- Modifiability: It should be possible to modify decoded data and encode it.

# Why not ...

We have evaluated a few alternatives before writing our binary decoding framework.

## ... Kaitai Struct?

Kaitai Struct is a framework that allows to
declare the structure of binary formats and to
derive parsers from such a structure declaration automatically.
In general, users are expected to:

1. Write/reuse a binary format description in Kaitai's DSL.
2. Let Kaitai generate deserialisation code for a specific language (e.g. C++ or JavaScript)
3. Use the generated code to parse files.

For example, let us consider a binary format `X` that
consists of two fields, `a` and `b`.
To parse this, Kaitai might generate a data type `struct X { a: T, b: U }`
(where `T` and `U` are placeholders for the types of `a` and `b`),
along with parsing code that deserialises files to `X` values.

Unfortunately, Kaitai has a few downsides:

- Error handling:
  When a Kaitai-generated parser encounters an error in a file,
  there is no clear way to obtain information about
  parts of the file that have been correctly parsed.
  For example, for the binary format `X`,
  if field `a` is valid, but field `b` is corrupt,
  we cannot get back information about `a`.
  However, getting such information is important in order to
  diagnose broken files in order to fix them.
- Reflection:
  Because Kaitai generates code for a single format at a time,
  it is difficult to use it for arbitrary formats.
  For example, given two binary formats `X` and `Y`,
  their corresponding data types do not implement a common *interface*
  that tells us e.g. that `X` has two fields called `"a"` and `"b"`.
  In order words, Kaitai does not provide a reflection mechanism.
  (On the other hand, this is precisely what is needed for the
  [Kaitai Web IDE](https://ide.kaitai.io/):
  Here, one can analyse arbitrary formats at run-time.
  This depends on compiling `.ksy` files with a special `--debug` flag,
  which is, however, hardly documented and seems to function differently
  on different backends <https://github.com/kaitai-io/kaitai_struct/issues/332>.)
- Source information:
  While the aforementioned `--debug` flag provides access to range data
  (at least for some backends), it does not provide granularity on the bit-level.
- Compilation:
  Kaitai generates code at compile-time.
  This makes it very hard to support arbitrary formats at run-time.
  An interpreter for Kaitai files would solve that issue, but alas,
  such an interpreter does not exist.
- Structure vs. logic:
  While Kaitai Struct --- as indicated by its name ---
  is very concise to capture *structure*, it is more difficult to
  use it to describe algorithms that are sometimes necessary to decode a format.

## ... WebAssembly?

WebAssembly is a format to store platform-independent code that
can be executed on a wide range of devices and in web browsers.
We have thought about using it as target platform to define binary decoders in.
This would allow using binary decoders from different host languages,
such as Go and Rust.
However, there is one huge problem:
We cannot easily share memory between WebAssembly and a host language like Rust.
This makes it impossible to pass a memory-mapped file from Rust to WebAssembly,
and to return data from WebAssembly that contains references to the memory-mapped file.
This is bad for performance and memory consumption,
because it effectively prevents zero-copy deserialisation.
