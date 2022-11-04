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


Install
============

You will need a running PostgreSQL install, and it's debug symbols.

For pgtracer itself you will need:
 - libunwind installed on the system
 - the [BPF Compiler Collection](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
 - several python packages as dependencies:
   - `psutil`
   - `pyelftools`

Support will vary depending on your Linux distribution, kernel version, and
library versions, as well as how PostgreSQL was compiled.

Please file a bug if it doesn't work as expected.

Ubuntu
------------

To install the debug symbols, install the `postgresql-version-dbgsym` package. You may have to enable additional repositories though.

To run pgtracer you will need some python packages as well as packages only available from the repos.

```
apt install python3-bpfcc python3-pip libunwind-dev
```

Then upgrade pip using pip:

```
pip install pip --upgrade
```

And you are now ready to install the pgtracer package itself:

```
git clone https://github.com/aiven/pgtracer.git
cd pgtracer
pip install .
```


Fedora
---------

To install the debugging symbols:

```
yum install dnf-utils
debuginfo-install postgresql-server
```

For the dependencies:

```
yum install python3-bcc libunwind  python3-pip libunwind-devel
```

Then install pgtracer itself:

```
git clone https://github.com/aiven/pgtracer.git
cd pgtracer
pip install pip --upgrade
pip install .
```



Arch Linux
------------

To install PostgreSQL debug symbols, as root:

```
pacman -S debuginfod
export DEBUGINFOD_URLS="https://debuginfod.archlinux.org/"
debuginfod-find debuginfo /usr/bin/postgres
```

To install the required packages:

```
pacman -S python-bcc libunwind python-pip
```

Then install the pgtracer package itself:

```
git clone https://github.com/aiven/pgtracer.git
cd pgtracer
pip install .
```


Usage
=============

Currently, only one script comes with pgtracer: `pgtrace_queries`.
Since pgtracer uses eBPF, it needs to be run as root.

```
usage: pgtrace_queries [-h] [--instrument [{TIMER,BUFFERS,ROWS,WAL,ALL} ...]] [--nodes-collection] pid

Dump a running backend execution plan

positional arguments:
  pid                   PID to connect to

options:
  -h, --help            show this help message and exit
  --instrument [{TIMER,BUFFERS,ROWS,WAL,ALL} ...], -I [{TIMER,BUFFERS,ROWS,WAL,ALL} ...]
                        Instrument flags to set. (warning: writes into backends memory!)
  --nodes-collection, -n
                        Collect information about individual execution nodes
```



Depending on the way the PostgreSQL binary have been compiled, you may need a
more recent pyelftools version than what is packaged with your distribution:
DWARF5 support is quite recent and continuously improving.





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
