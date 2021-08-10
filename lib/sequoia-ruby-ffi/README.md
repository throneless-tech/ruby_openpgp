# sequoia-ruby-ffi

This project contains ruby-bindings for Sequoia-PGP (v1.0.0), an
OpenPGP implementation in Rust. For the bindings the C-API (v.0.22.0)
of Sequioa-PGP and the ruby-ffi gem are used. This project is still in
its beginning.

# Future Work

Until now, there are only some functions from Sequoia-PGP available in
these bindings. Additionally there are no high-level abstractions, as
ruby-programmers would expect them.

# How to specify the location of the shared object

If you haven't installed Sequoia-PGP under a standard path as
/usr/lib, you can specify the location of the shared object through
the LD_LIBRARY_PATH environment variable.

You can for example call your program directly with LD_LIBRARY_PATH
set:

```bash
$ LD_LIBRARY_PATH=/path/to/sequoia ruby tc_io.rb
```

or export the environment variable.

# Contribution

Contributors are welcome! :) Just get in touch or make pull requests :)

# License

This project is licensed under the MIT license.