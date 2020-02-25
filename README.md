# Instructions 
- cd to `$WORKSPACE`
- clone zeek 3.0.1 (`git clone --recursive --branch v3.0.1 https://github.com/zeek/zeek`)
- cd to `$WORKSPACE/zeek/src/analyzer/protocol`
- clone this repo
- update `ZEEK_ROOT` and `OUTPUT_DIR`, and `ZEEK_PARAMS` in the makefile.
- run `make conf-local`, `make build-local`, `make run-local` within this repo to link to and build the parent zeek installation. Run `make dep-local` to install ubuntu-style dependencies.