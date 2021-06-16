## AndFriFuzz

Android Native So Fuzz. Working in Real machine efficiently.

<img src="https://github.com/idhyt/AndroidFridaFuzz/raw/master/andff_demo.gif" alt="show" />

## About

Refactor based on [frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer)

- [x] AFL(mutator) + Stalker(coverage feedback) + Process.setExceptionHandler(watch point)
- [x] Customize the target parameter type
- [x] AFL UI

## Usage

*In Android Device*

* root, and run [frida server](https://github.com/frida/frida/releases).

* install the fuzz app like `./tests/aff-test.apk`

*In Host*

* install adb-tools, make sure adb commmand enable.

* install python, npm.

* install depends by:

```shell
make env
```

* write the fuzz target configuration file like:

```json
{
  "compile": {
    "template": "native.js",
    "target_module": "libaff-test.so",
    "target_function": "vul_func_buf",
    "ret_type": "int",
    "args": [
      {"type": "pointer", "size": 0},
      {"type": "pbl_int", "size": 0}
    ]
  },
  "fcj": "./node_modules/frida-compile/bin/compile.js",
  "target": "com.example.aff",
  "seeds": "./tests/seeds",
  "script": "./tests/compiled.js"
}
```

* build js code by:

```shell
make build
```

* run fuzz by:

```shell
make run
```

you will see:

```shell

╰─ make run
python fuzz.py --fuzz ./tests/config.json
 >> find target function (libaff-test.so->vul_func_buf) at 0x725a4f1e7c
 >> Agent loaded!
 >> Dry run...

                    Android Frida Fuzz(com.example.aff)
┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐
│        run time : 0 hrs, 0 min, 5 sec                │  cycles done : 9      │
│   last new path : 0 hrs, 0 min, 3 sec                │  total paths : 4      │
│ last uniq crash : 0 hrs, 0 min, 5 sec                │ uniq crashes : 1      │
│  last uniq hang : not seen yet                       │   uniq hangs : 0      │
├─ cycle progress ────────────────────┬─ map coverage ─┴───────────────────────┤
│  now processing : 2/4 (50.00%)      │   map density : 10.94 %                │
├─ stage progress ────────────────────┼─ findings in depth ────────────────────┤
│  now trying : splice-3              │ favored paths : 2 (50.00%)             │
│ stage execs : 480/1280 (37.50%)     │                                        │
│ total execs : 13282                 │ total crashes : 1                      │
│  exec speed : 1214/sec              │                                        │
├─ fuzzing strategy yields ───────────┴───────────────┬─ path geometry ────────┤
│       havoc : 0/0k, 0/0                             │  pend fav : 2          │
└─────────────────────────────────────────────────────┴────────────────────────┘


 >> Starting fuzzing loop...

============= CRASH (breakpoint) =============
breakpoint triggered

pc : 0x71faa5bc2c        sp : 0x72559d3600
x0 : 0x0                 x1 : 0x72e6b1f4d0
x2 : 0x8                 x3 : 0x443d5d5b66756200
x4 : 0x725a51522c        x5 : 0x7259c00537
x6 : 0x42413d5d5b667562  x7 : 0x42413d5d5b667562
x8 : 0x391ae8342e5d5946  x9 : 0x391ae8342e5d5946
x10: 0x0                 x11: 0x72559d3374
x12: 0x3                 x13: 0x10
x14: 0x72e6b1f40a        x15: 0x72e6a59bd3
x16: 0x72e75a5170        x17: 0x72ebaf14b8
x18: 0x0                 x19: 0x20
x20: 0x725d142b20        x21: 0x72559d3708
x22: 0x0                 x23: 0x72559d3730
x24: 0x72561ad6b0        x25: 0x725d109ab8
x26: 0x0                 x27: 0x2
x28: 0x2                 fp : 0x72559d3610
lr : 0x725a4f1ed8

saving at data/com.example.aff_2021-01-26_17-17-05/crash_splice-3_breakpoint_1611652631

```


## TODO

this demo is experimental of my tool chain, it's not complete, but is effective. 

if you want to use it to find some app bugs, there's still some work to do.
