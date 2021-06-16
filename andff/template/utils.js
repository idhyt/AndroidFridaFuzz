exports.get_target_address = function (m, f) {
    var addr = 0;
    if(isNaN(f)) {
      // is function name
      addr = Module.findExportByName(m, f);
    } else {
      var mBase = Module.findBaseAddress(m);
      addr = mBase.add(parseInt(f));
    }
    // console.log(addr);
    return addr;
}


/*
  buff, char *
  buff_len, buff.length
  int, 4bit.
  int64, 8bit.
  pbl, prev buffer len.

  in frida context: 
    p = Uint8Array.buffer.unwrap()
    args = [
      {"type": "", "size": 0},                          // params 1
      {"type": "int", "size": 4},                       // params 2
      {"type": "point", "size": 20},                    // params 3
    ]
*/
var get_target_params = function (payload, args) {
  var payloadStart = payload.buffer.unwrap();
  var payloadEnd = payloadStart.add(payload.length);

  var curr = payloadStart;
  var next = curr;
  var params = [];
  var remain_len = payload.length;

  for (let index = 0; index < args.length; index++) {
    var type = args[index]["type"];
    var size = args[index]["size"];
    next = curr.add(size);
    remain_len -= size;

    if (next > payloadEnd) {
      if (type === "pointer") {
        params.push(curr);
      } else
      if (type.indexOf("int") === 0) {
        params.push(0);
      } else {
        throw "ERROR: unsupported type for " + type;
      }
      next = curr;
    } else {
      if (type === "int") {
        params.push(curr.readInt());
      } else
      if (type === "int64") {
        params.push(curr.readDouble());
      } else
      if (type === "pointer") {
        params.push(curr);
      } else
      if (type.indexOf("pbl") === 0) {
        params.push(remain_len);
      } 
      else {
        throw "ERROR: unsupported type for " + type;
      }
    }
    curr = next;
  }
  return params;
}


exports.call_target_function = function (payload, handle, args) {
  // console.log('payload: ' + payload + ', handle: ' + handle + ', args: ' + args + ', len: ' + args.length);
  var params = get_target_params(payload, args);
  /*
  params.forEach(element => {
    console.log('0x' + element.toString(16));
  });
  throw "debug...";
  return eval(`
    handle(${params.join(",")});
  `);
  */
  return handle.apply(null, params);
}


function Uint8ArrayToString(fileData){
  var dataString = "";
  for (var i = 0; i < fileData.length; i++) {
    dataString += String.fromCharCode(fileData[i]);
  }

  return dataString
}


function stringToUint8Array(str){
  var arr = [];
  for (var i = 0, j = str.length; i < j; ++i) {
    arr.push(str.charCodeAt(i));
  }

  var tmpUint8Array = new Uint8Array(arr);
  return tmpUint8Array
}


