erlang_hbbft
=====

[![Build Status](https://badge.buildkite.com/e794bf0f28123f75870633e8f4a9fda955cbe19e981d12a5d3.svg?branch=master)](https://buildkite.com/helium/hbbft)

Erlang implementation of HoneyBadgerBFT's protocols.

The HoneyBadgerBFT paper defines 5 protocols:

* HoneyBadgerBFT - the top level protocol, runs a new instance of ACS each round
* Asynchronous Common Subset (ACS) - uses RBC and BBA to agree on set of
  encrypted 'bundles' of transactions
* Reliable Broadcast (RBC) - uses erasure coding to disseminate an encrypted bundle
* Binary Byzantine Agreement (BBA) - uses a common coin to agree that a majority
  of nodes agree that a RBC completed
* Common Coin - uses threshold signatures to allow nodes to construct a common
  random value used as a 'coin flip' in BBA

The protocols are implemented in a somewhat unconventional way, they are
implemented as pure data structures that take inputs (messages) and (sometimes)
return outputs or results. They have no notion themselves of networking, time or
actor identity (actors are simply numbered 0..N-1).

External code is expected to provide networking, serialization and a mapping
from real actor identity (eg PKI public keys and signatures or IP addresses,
whatever) to a consistent index into the consensus group.

The sub protocols are embedded in their parent protocols and their messages get
'wrapped' by their containing protocols (and un-wrapped upon ingest). This makes
testing them individually and composing them very easy.

Build
-----

    $ make

Test
-----

    $ make test


TypeCheck
-----

    $ make typecheck


Coverage
-----

    $ make cover

References
-----

* [Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)
