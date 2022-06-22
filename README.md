PGTracer
========

PGTracer is a collection of tools to trace queries, execution plans and more in
PostgreSQL, using eBPF.

Overview
========

PGTracer offers a way to instrument PostgreSQL, using the Linux eBPF facility.
As it does advanced memory access, it needs the PostgreSQL debug symbols to
resolve symbols and offsets in structs.

Features
============


Setup
============

You will need:
* [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* [pyelftools](https://github.com/eliben/pyelftools)

License
=======
pgtracer is licensed under the PostgreSQL license. Full license text is available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

Contact
============
Bug reports and patches are very welcome, please post them as GitHub issues and pull requests at https://github.com/aiven/pgtracer .
To report any possible vulnerabilities or other serious issues please see our [security](SECURITY.md) policy.
