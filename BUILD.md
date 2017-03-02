Building Metre
=======

Cooking time
----

Approximately one minute.

Ingredients
----

* libunbound 2.0
* libevent 2.0
* OpenSSL 1.0.2
* git
* CMake 2.8 (or so)

Source control is within Git (github is the public one). The software is built using CMake
for production builds - there's a (broken) Makefile as well which you should ignore.

libunbound provides async DNS, including DNSSEC, and libevent provides buffered async
I/O, which should work well both on Linux and Windows.

Finally OpenSSL supplies crypto, X.509 primitives, and TLS. This was chosen mostly due
to OpenSSL having a FIPS certificate.

An Ubuntu/Debian APT line reads like:

```sh
apt-get install git build-essential g++ cmake libicu-dev libssl-dev libevent-dev libunbound-dev
```

Method
----

First, clone the source. You can access this anonymously via HTTPS:

```sh
git clone https://github.com/dwd/metre
```

Enter the directory:

```sh
cd metre
```

*Optionally* you can generate new DH parameter files using `openssl dhparam ${DHSIZE} -C`
to replace those within the `./gen` directory. DH parameters are not private, but using
the same ones as everyone else might mean that weaker ones, at least, could be cracked.

Metre may, in the future, generate the shorter keys on boot to improve their security.

Now initialize and clone the submodules:

```sh
git submodule update --init
```

Create a build directory and change to it. I usually use something like "build" within the
source directory, but you can do anything you like, really. The instructions will assume
you do **EXACTLY AS I SAY** however:

```sh
mkdir build
cd build
```

Now let cmake do its magic:

```sh
cmake ..
```

And then, finally, you can just build - the build is very parallel, so use all your cores. I
have 12. Go me:

```sh
make -j12
```

You'll now have the executable built as `./build/metre`, relative to the source tree. You'll
want to look at the bad example config file at `./metre.conf.xml` and you'll need a DNSSEC
keys file, which you could make *insecurely* by `dig . DNSSEC > ./keys`. 

Serves
----

Around 100k domains, I suspect.