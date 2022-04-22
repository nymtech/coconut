Coconut
=======

Coconut [[paper](https://arxiv.org/abs/1802.07344)] is a distributed cryptographic signing scheme providing a high degree of privacy for its users. You can find an overview of how to use it in the [Coconut section](https://nymtech.net/docs/overview/private-access-control/) of the Nym documentation. 

A [simple explanation](https://constructiveproof.com/posts/2020-03-24-nym-credentials-overview/) is also available in blog form. 

On branch `develop` you can find the implementation of the original Coconut scheme as described in [[paper](https://arxiv.org/abs/1802.07344)].

On branch `research/pedersen_commitments` you can find the implementation of the extended Coconut scheme in which ElGamal encryption has been replaced 
with Pedersen commitments (to improve performance) and the show protocol has been improved to provide unlinkability against unbounded adversaries. 
The full description of the updated protocols and the security analysis are presented in [[paper](https://eprint.iacr.org/2022/011.pdf)]. 

This repo contains Go and Rust implementations of Coconut. 

Note: Currently the libraries are **not** interoperable - different methods of curve hash are being used.

[comment]: <> (They are interoperable - credentials created and re-randomized in Rust can be verified in Go, and vice versa.)

License
-------

Coconut is released under the Apache-2.0 license. See inside the LICENSES folder of each project. 