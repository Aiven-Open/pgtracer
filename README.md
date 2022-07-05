PGTracer
========

PGTracer is a collection of tools to trace queries, execution plans and more in
PostgreSQL®, using eBPF.

Overview
========

PGTracer offers a way to instrument PostgreSQL, using the Linux eBPF facility.
As it does advanced memory access, it needs the PostgreSQL debug symbols to
resolve symbols and offsets in structs.

Features
============

* Attach to a running PostgreSQL backend, and dump every executed query along
  with it's search path
* Optionally turn on instrumentation (just like EXPLAIN ANALYZE does) to gather
  more information

Planned features:
* Gather information about individual execution nodes to print query plans
* Gather system information and link them to individual nodes (think syscalls,
  IO, memory allocation...)
* Build a TUI to explore the data
* Allow to follow a transaction


Setup
============

You will need:
* [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* [pyelftools](https://github.com/eliben/pyelftools)
* [psutil](https://github.com/giampaolo/psutil)

Depending on the way the PostgreSQL binary have been compiled, you may need a
more recent pyelftools version than what is packaged with your distribution:
DWARF5 support is quite recent and continuously improving.

Support will vary depending on your Linux distribution, kernel version, and
library versions. Please file a bug if it doesn't work as expected.


License
=======
pgtracer is licensed under the PostgreSQL license. Full license text is available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

Contact
============
Bug reports and patches are very welcome, please post them as GitHub issues and pull requests at https://github.com/aiven/pgtracer .
To report any possible vulnerabilities or other serious issues please see our [security](SECURITY.md) policy.

Trademarks
==========

The terms Postgres and PostgreSQL are registered trademarks of the PostgreSQL Community Association of Canada.
