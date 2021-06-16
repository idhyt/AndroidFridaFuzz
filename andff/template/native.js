var config = require("../compile/config.js");

// if you want to modify config vars you need to do it before including the fuzz module
config.MAP_SIZE = 128;

var fuzz = require("../compile");
var utils = require("./utils.js");

var TARGET_MODULE = "REP_TARGET_MODULE";
var TARGET_FUNCTION = "REP_TARGET_FUNCTION";
var TARGET_RET_TYPE = "REP_TARGET_RET_TYPE";
var TARGET_ARGS_PROTO = REP_TARGET_ARGS_PROTO;
var TARGET_ARGS_TYPES = REP_TARGET_ARGS_TYPES;

var target_addr = utils.get_target_address(TARGET_MODULE, TARGET_FUNCTION);
send({"event": "clog", "data": "find target function (" + TARGET_MODULE + '->' + TARGET_FUNCTION + ') at ' + target_addr});

// { traps: 'all' } is needed for stalking
var func_handle = new NativeFunction(target_addr, TARGET_RET_TYPE, TARGET_ARGS_TYPES, { traps: 'all' });

fuzz.target_module = TARGET_MODULE;

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {
  // var payload_mem = payload.buffer.unwrap();

  // var ret = func_handle(payload_mem, payload.length);

  // console.log("ret = " + ret);
  var ret = utils.call_target_function(payload, func_handle, TARGET_ARGS_PROTO);
}

// console.log (" >> Agent loaded!");
send({"event": "clog", "data": "Agent loaded!"});
