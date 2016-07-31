Building Metre
=======

Cooking time
----

Approximately one minute.

Ingredients
----

* libunbound 2.0
* OpenSSL 1.0.2
* git
* CMake 2.8 (or so)

Method
----

First, clone the source:

```sh
git clone https://github.com/dwd/metre
```

Enter the directory:

```sh
cd metre
```

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

You'll now have the executable built as `./build/metre`, relative to the source tree.

Serves
----

Around 100k domains, I suspect.