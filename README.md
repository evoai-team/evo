EvoaiCoin Core integration/staging tree
=====================================

**WLaunched as an open source cryptocurrency in 31 Fri 2025. Evoai is a decentralized and secure masternode network project with long term goals. Our focus is to create a cryptocurrency that is accessible to all as a global payment platform for developers, investors and the general public alike.**

**Anyone trying to sell you a photonic miner is trying to scam you.**

-evoai team

https://evoai.top/

What is EvoaiCoin (EvoaiCoin)?
-------------------------------

EvoaiCoin is a fork of Bitcoin aiming to reduce mining energy consumption via compatability with cutting edge optical Evoai is leveraging the best minds in blockchain technology with a mature ecosystem and progression driven by a dedicated foundation team.

We aim to build a global payment platform that cryptocurrency is not only for tech-savvy people. We wish Evoai will be used widely in every city in the world.


License
-------

EvoaiCoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/evoai-team/evo.git) are created
regularly to indicate new official, stable release versions of EvoaiCoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.


Contributors
------------

We thank the Bitcoin Core contributors for their effort.

We also thank everyone who believed in us.
