# OptiWISE
OptiWISE is a profiling tool providing granular Cycles per Instruction (CPI) and
Instructions per Cycle (IPC) analysis of x86-64 and AArch64 Linux programs.  It
combines the information from two runs of the program: one using low-overhead
sampling, and the other using high-overhead dynamic instrumentation.  The
results of these two runs are then combined to give per instruction, per basic
block, per loop, and per function overheads. This information can be viewed in
both a machine readable (CSV and YAML) and human friendly (interactive HTML user
interface) form. If you use OptiWISE in your work please cite our [CGO24 publication](#publication).

<video src="https://github.com/CompArchCam/optiwise/assets/1593708/10b82c14-8276-412a-a56d-e462cceeb413"></video>

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
the `optiwise_result/analyze/result` directory. The `--gui` flag can be included
to generate an HTML and JavaScript based interface at
`optiwise_result/gui/result/index.html` for viewing the results e.g.

```sh
optiwise run --gui -- /usr/bin/echo hello
```

For more fine grain control, see `optiwise help`.  The subcommands of OptiWISE
will allow you to configure the individual jobs in OptiWISE and configure
various additional options.

# Publication

OptiWISE is developed at the University of Cambridge, Department of Computer Science and Technology. You can find more information about OptiWISE in our publication. Please cite this if you use OptiWISE in your work.

Y. Guo et al., ["OptiWISE: Combining Sampling and Instrumentation for Granular CPI Analysis,"](https://doi.org/10.1109/CGO57630.2024.10444771) 2024 IEEE/ACM International Symposium on Code Generation and Optimization (CGO), Edinburgh, United Kingdom, 2024, pp. 373-385, doi: 10.1109/CGO57630.2024.10444771.


