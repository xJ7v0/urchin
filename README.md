
#    urchin libc

urchin is an anti-rop, anti-ret2libc that aimes for speed. it is 
implementation of the standard C library targetting the Linux syscall
API, suitable for use in a wide range of deployment environments. urchin
offers lightweight code, speed improvements over musl
and low runtime overhead, strong fail-safe guarantees under correct
usage, and correctness in the sense of standards conformance and
safety. musl is built on the principle that these goals are best
achieved through simple code that is easy to understand and maintain.

The 0.1 release series for urchin features coverage for all interfaces
defined in ISO C99 and POSIX 2008 base, along with a number of
non-standardized interfaces for compatibility with Linux, BSD, and
glibc functionality.

For basic installation instructions, see the included INSTALL file.
Information on full musl-targeted compiler toolchains, system
bootstrapping, and Linux distributions built on musl can be found on
the project website:


[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/xJ7v0/urchin/blob/xJ7v0/master/COPYRIGHT)
