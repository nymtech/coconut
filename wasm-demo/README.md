Coconut Webassembly Demo
=========================

Coconut can be run completely inside a web browser environment. 

Prerequisites
--------------

* [Rust](https://www.rust-lang.org/tools/install) (works with 1.64)
* [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)


Building
--------

```
cd coconut-wasm-wrapper
wasm-pack build --scope nymproject
```

Running the demo
----------------

To run the demo run the following: 

`npm install && npm run start`
