The ntop source for nDPI is not written to be included in the Linux
kernel.  A number of files need minor patching to make them work in
that environment.  At build time, a version of the ntop source copied
to `src/ndpi-netfilger/ndpi_cpy/` and used to build ndpi-netfilter.
Through the history of this project, there have been different
approaches to how the code is adapted.

* The [original ndpi-netfilter
project](https://github.com/betolj/ndpi-netfilter) copied ntop files
into a local `nDPI-patch/` directory.

* [Prizraksarvar](https://github.com/prizraksarvar/ndpi-netfilter)
took the approach of forking the ntop repository and making local
changes in that fork.

* This version uses the ntop code as a submodule (so it is easier to
track changes) and uses patch files in `nDPI-patch/` to adapt that
code to the kernel environment.

## Scripts

Several scripts are provided to aid in patching the nDPI source.  All
three scripts are in the `nDPI-patch/` directory.  You may find it helpful to go there and do

```
  export PATH=$PATH:`pwd`
```

### cndpi - Copy nDPI

This script copies a file that needs to be patched from the nDPI submodule to the current directlry.  Use it like:

```
  cd nDPI-patch/src/lib
  ../../cndpi ndpi_main.c
```

### pndpi - Prepare a patch file

This script created a `.patch` file for a nDPI source file.  Use it like:

```
  ../../pndpi ndpi_main.c
```

then check in the patch file (e.g., `ndpi_main.c.patch`).

### rndpi - Repatch an nDPI file

This script can be used to refresh an existing patch file.  Minor
changes in the nDPI source will lead to patching applying but a few
lines away from the original patch.

To remove the warnings in the build output from minor line number changes, use it like:

```
  ../../rndpi ndpi_main.c
```

then check in the modified patch file.

To make additional changes for a file that already has a patch, use it like:

```
  ../../rndpi ndpi_main.c
```

Then edit the file (e.g., `ndpi_main.c`) to address build issues and then use `pndip` to update the patch file before checking it it to the repository.

### Example

To patch errors in `src/ndpi_cpy/<somepath>/somefile.c`:
1. Go to `nDPI-patch/<somepath>/`
1. If there is no `somefile.c.patch`, copy the original file with `cndpi somefile.c`
1. If there is already a `somefile.c.patch`, refresh the source with `rndpi somefile.c`
1. Edit `somefile.c` to make fix the problem.
1. Create a new patch with `pndpi somefile.c`
1. Commit the patch (`git add somefile.c.patch && git commit`)

## Common Problems and Solutions

### Protocol count mismatch

If you see build output like
```
ndpi-netfilter/src/main.c:62:1: error: static assertion failed: "nDPI and ndpi-netfilter protocol counts do not match."
   62 | _Static_assert(sizeof(prot_long_str)/sizeof(char*)
      | ^~~~~~~~~~~~~~
make[3]: *** [scripts/Makefile.build:271: /home/chrisn/src/6/ndpi-netfilter/src/main.o] Error 1
```

It most likely means that the nDPI project has added protocols.
1. Compare `nDPI/src/include/ndpi_protocol_ids.h` to `src/xt_ndpi.h`.  You can get started by going into the nDPI submodule and doing something like:
```
git diff origin/3.4-stable..origin/dev src/include/ndpi_protocol_ids.h
```
2. In `src/xt_ndpi.h`, add rows to `NDPI_PROTOCOL_LONG_STRING` and
`NDPI_PROTOCOL_SHORT_STRING` for the new protocols.
1. In `src/Makefile`, add lines to the definition of `xt_ndpi-y` for
the new protocols. (They should start with `${NDPI_PRO}/` and end with
the name of the object file for the new protocol.  Try to keep those lines in alphabetical order.)
1. Try to build.  Add patching as needed. (See below.)

### Reversed patch detected

If you see build output like
```
patching file ndpi_cpy/include/ndpi_define.h
Reversed (or previously applied) patch detected!  Assume -R? [n] n
```

It most likely means that you haven't built the nDPI submodule yet,
`ndpi_define.h` is created as part of that build.  Abort the
`ndpi-netfilter` build and go build nDPI first.

### Standard Headers ###

Include files like `stdint.h`, `stdlib.h`, `stdio.h`, `stdarg.h` are
not available in the kernel build environment and trying to use them
-- as many of the nDPI `.c` files do -- will result in a build error.

This also sometimes occurs with include files delimited by angle
brackets, `<` and `>`.

You will see errors like:

```
/home/chrisn/src/ndpi-netfilter/src/ndpi_cpy/lib/ndpi_main.c:24:10: fatal error: stdlib.h: No such file or directory
   24 | #include <stdlib.h>
      |          ^~~~~~~~~~
compilation terminated.
```

Edit `somefile.c`
1. Before the first `#include` of a standard header, add `#ifndef __KERNEL__`
1. After the last `#include` of a standard header, add `#endif`

Sometimes this will result in undefined types like `uint_32t`.  If so, before the `#endif` you added, add two more lines:
```
#else
#include <linux/types.h>
```

### For loop variables

The kernel build environment uses a fairly old C standard which does not allow loop control variables to be declared in the loop header.

```
/home/chrisn/src/ndpi-netfilter/src/ndpi_cpy/lib/protocols/http.c:149:6: error: ‘for’ loop initial declarations are only allowed in C99 or C11 mode
  149 |      for(int i = 0; binary_file_ext[i] != NULL; i++) {
      |      ^~~
/home/chrisn/src/6/ndpi-netfilter/src/ndpi_cpy/lib/protocols/http.c:149:6: note: use option ‘-std=c99’, ‘-std=gnu99’, ‘-std=c11’ or ‘-std=gnu11’ to compile your code
```

Edit `somefile.c` to bring the declaration out of the loop header.
That is, change
```
for(int i = ...)
```
to
```
int i;
for(i = ...)
```
### Memory Management Functions

The standard C memory management functions `malloc()` and `free()`
(and related `calloc()` and `realloc()`) do not exist in the kernel
environment.  Generally, nDPI provides alternatives with an `ndpi_`
prefix so if your build is missing one of the standard functions,
replace `malloc()` with `ndpi_malloc()`, etc.

Some of the existing patches conditionally replace `free()` with
`kfree()`, the kernel equivalent.  This might be revisited in the
future for consistency.


### Assertions

The `assert()` macro in C can be used to test conditions at runtime.
When the condition is false, the assertion fails and the program
crashes.  This is not great behavior for the kernel so there is no
`assert()` in the kernel environment.

If you get an error about `assert()` being missing, edit the file and
change:

```
#include <assert.h>
```
to
```
#ifndef __KERNEL__
#include <assert.h>
#else
#define assert(x)
#endif
```

### Kernel Version Mismatch

After version 5.4, the Linux kernel changed how it keeps track of
time. `nDPI` has 5.4 assumptions baked in.  If you see an error like
```
unkown type name 'time_t'
```
during the build process, this may mean `time_t` is no longer supported 
and you will need to rollback. You should also see a line like
```
make[2]: Leaving directory '/usr/src/linux-headers-5.8.0-1040-generic'
```
giving you insight on which kernel version you are building with.

To rollback:
1. Install the 5.4 kernel then reboot
    ```
    $ sudo apt install linux-generic
    $ reboot
    ```
1. Log back in and list the kernel packages for the version you are using
    ```
    $ dpkg --list | grep <version>
    ```
1. Remove the `headers`, `modules`, and `modules-extra` packages for the version you were using and reboot again
    ```
    $ sudo apt remove <package1> <package2> ...
    $ reboot
    ```