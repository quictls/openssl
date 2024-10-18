HOW TO CONTRIBUTE TO QuicTLS
============================

Please visit our [Getting Started] page for other ideas about how to contribute.

  [Getting Started]: <https://www.openssl.org/community/getting-started.html>

Development is done on GitHub in the [quictls/quictls] repository.

  [quictls/quictls]: <https://github.com/quictls/quictls>

To request new a feature, ask a question, or report a bug,
please open an [issue on GitHub](https://github.com/quictls/quictls/issues).

To submit a patch or implement a new feature, please open a
[pull request on GitHub](https://github.com/quictls/quictls/pulls).
If you are thinking of making a large contribution,
open an issue for it before starting work, to get comments from the community.
Someone may be already working on the same thing,
or there may be special reasons why a feature is not implemented.

To make it easier to review and accept your pull request, please follow these
guidelines:

 1. All source files should start with the following text (with
    appropriate comment characters at the start of each line and the
    year(s) updated):

    ```
        Copyright 20xx-20yy The QuicTLS Project Authors. All Rights Reserved.

        Licensed under the Apache License 2.0 (the "License").  You may not use
        this file except in compliance with the License.  You can obtain a copy
        in the file LICENSE in the source distribution or at
        https://www.apache.org/licenses/LICENSE-2.0
    ```

 2. Patches should be as current as possible; expect to have to rebase
    often. We do not accept merge commits, you will have to remove them
    (usually by rebasing) before it will be acceptable.

 3. Code provided should follow our coding style and compile without warnings.
    There is a [Perl tool](util/check-format.pl) that helps
    finding code formatting mistakes and other coding style nits.
    Where `gcc` or `clang` is available, you should use the
    `--strict-warnings` `Configure` option.  QuicTLS compiles on many varied
    platforms: try to ensure you only use portable features.
    Clean builds via GitHub Actions are required. They are started automatically
    whenever a PR is created or updated by committers.

 4. When at all possible, code contributions should include tests. These can
    either be added to an existing test, or completely new.  Please see
    [test/README.md](test/README.md) for information on the test framework.

 5. New features or changed functionality must include
    documentation. Please look at the `.pod` files in `doc/man[1357]` for
    examples of our style. Run `make doc-nits` to make sure that your
    documentation changes are clean.

 6. For user visible changes (API changes, behaviour changes, ...),
    consider adding a note in [CHANGES.md](CHANGES.md).
    This could be a summarising description of the change, and could
    explain the grander details.
    Have a look through existing entries for inspiration.
    Please note that this is NOT simply a copy of git-log one-liners.
    Also note that security fixes get an entry in [CHANGES.md](CHANGES.md).
    This file helps users get more in-depth information of what comes
    with a specific release without having to sift through the higher
    noise ratio in git-log.

 7. Guidelines how to integrate error output of new crypto library modules
    can be found in [crypto/err/README.md](crypto/err/README.md).
