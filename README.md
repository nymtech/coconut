Coconut
=======

Coconut [[paper](https://arxiv.org/abs/1802.07344)] is a distributed cryptographic signing scheme providing a high degree of privacy for its users. You can find an overview of how to use it in the [Coconut section](https://nymtech.net/docs/overview/private-access-control/) of the Nym documentation. 

A [simple explanation](https://constructiveproof.com/posts/2020-03-24-nym-credentials-overview/) is also available in blog form. 

This repo contains Go and Rust implementations of Coconut. 

Note: Currently the libraries are **not** interoperable - different methods of curve hash are being used.

[comment]: <> (They are interoperable - credentials created and re-randomized in Rust can be verified in Go, and vice versa.)


Running the Rust CLI demo
================

First, install Rust for your operating system. Instructions can be found at the [Rust](https://rust-lang.org) website.

Once Rust is installed:

```
git clone https://github.com/nymtech/coconut.git

cd coconut/cli-demo-rs
cargo run 
```

Follow the prompts to demonstrate Coconut functionality.

We suggest: 

4 issuing authorities
Threshold of 3
2 public attributes
1 private attribute


Running the Webassembly demo
==================

Instructions are in the [webassembly-demo README](wasm-demo)



License
-------

Coconut is released under the Apache-2.0 license. See inside the LICENSES folder of each project. 

This project was partially funded through the NGI0 PET Fund, a fund established by NL.net with financial support from the European Commission's NGI programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825310.
