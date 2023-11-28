# OptiWISE
OptiWISE is a profiling tool providing granular Cycles per Instruction (CPI) and
Instructions per Cycle (IPC) analysis of x86-64 and AArch64 Linux programs.  It
combines the information from two runs of the program: one using low-overhead
sampling, and the other using high-overhead dynamic instrumentation.  The
results of these two runs are then combined to give per instruction, per basic
block, per loop, and per function overheads.

# Building

Running `make` will generate `install_dir.ARCH` where `ARCH` is the ISA for
example `x86_64`.  The `optiwise` command is available in the `bin`
subdirectory of this. Consequently running:

```sh
export PATH=$(pwd)/install_dir.x86_64/bin:$PATH
```

Will temporarily add `optiwise` to your command line.

Running `sudo make install` will install to `/usr/bin/optiwise` and
`/usr/share/optiwise` instead, meaning `optiwise` will be available on the
command line by default.

# Usage

A simple example would be:

```sh
optiwise run -- /usr/bin/echo hello
```

would cause OptiWISE to profile the program `/usr/bin/echo` with the argument
`hello`.  Note that this will run that program twice.  Results will be placed in
the `optiwise_result/analyze/result` directory.

For more fine grain control, see `optiwise help`.  The subcommands of OptiWISE
will allow you to configure the individual jobs in OptiWISE and configure
various additional options.
