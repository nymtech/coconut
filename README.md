Coconut
=======

Coconut [[paper](https://arxiv.org/abs/1802.07344)] is a distributed cryptographic signing scheme providing a high degree of privacy for its users. You can find an overview of how to use it in the [Coconut section](https://nymtech.net/docs/stable/overview/private-access-control/) of the Nym documentation. 

A [simple explanation](https://constructiveproof.com/posts/2020-03-24-nym-credentials-overview/) is also available in blog form. 

This repo contains Go and Rust implementations of Coconut. 

Note: Currently the libraries are **not** interoperable - different methods of curve hash are being used.

[comment]: <> (They are interoperable - credentials created and re-randomized in Rust can be verified in Go, and vice versa.)

License
-------

Coconut is released under the Apache-2.0 license. See inside the LICENSES folder of each project. 
