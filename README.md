What This Is
============
Long ago QUIC was created. For the past years Akamai and Microsoft have
collaborated on maintaining QUIC support via the BoringSSL APIs. However,
OpenSSL focused on their own implementation, deprioritizing other features and
improvements.

We're focused on treating the most important security protocol in the world,
and the implementation that powers cryptography across the open source
ecosystem with the importance and care it deserves.

We're going to keep API compatibility, but add new APIs that serve
programmers better, remove old cruft and deepen deprecation to help migrate
to a better world

What about branches?

What about FIPS?
----------------

Thanks to the provider interface we can load the OpenSSL FIPS module, and
will continue to do so. At some point we'll discuss how to get a FIPS
certification that really works for the open source world.

How can I contribute?
---------------------

Open a PR! Your code must be Apache 2 licensed. We are interested in
expanding compatibility with BoringSSL and LibreSSL, simplifying and
improving the security of some grotty code, cleaning this up, and new
features, even before RFCs are final.

We're also interested in KEM interfaces and postquantum algorithms, and if an
issue appeals to you, feel free to jump in and get started on it.

However, there's a bunch of design stuff that also needs to happen, but we'll
make sure to have the conversation in an open manner.

What about sonames and the like?
--------------------------------

So far we haven't changed them, but we likely will. At the same time API and
generally ABI compatibility is a big priority for us.


Who are you?
------------

This is a collaborative effort between [Akamai](https://www.akamai.com) and
[Microsoft](https://www.microsoft.com). We welcome anyone to contribute and
join. We are working on setting up more formal structures and welcome
participation beyond writing code as well.
