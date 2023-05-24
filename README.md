What This Is
============

This is a branch of the `openssl-3.1.0+quic` branch.  That README file has been
moved to
[README-QuicTLS.md](https://github.com/quictls/openssl/blob/openssl-3.1.0%2Bquic/README-QuicTLS.md)

This branch has the following locking performance fixes added:

- [Avoid taking a write lock in ossl_provider_doall_activated()](https://github.com/openssl/openssl/pull/20927)
- [Avoid taking a write lock in RAND_get_rand_method()](https://github.com/openssl/openssl/pull/20929)
- [Don't take a write lock when freeing an EVP_PKEY](https://github.com/openssl/openssl/pull/20932)
- [When we're just reading EX_CALLBACK data just get a read lock](https://github.com/openssl/openssl/pull/20943)
- [Modify ENGINE_pkey_asn1_find_str() to use a read lock instead of a write](https://github.com/openssl/openssl/pull/20950)*
- [Optimise some X509_STORE related locking](https://github.com/openssl/openssl/pull/20952)
- [Optimise locking in rsa_get_blinding()](https://github.com/openssl/openssl/pull/20953)
- [Don't get a lock when querying the parent reseed_count (alternative version)](https://github.com/openssl/openssl/pull/20970)*

All the PR's were cloned locally. Most of the patches were done by using
`format-patch` specifying the number of commits to format, and then doing
`am`. Some had to be done by using `diff` and `patch` by hand; those are
marked in the list above with an asterisk.
