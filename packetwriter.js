var toTwos = function (buff) {
  var neg = buff.neg;
  
  while (buff.length > 2 && buff[0] === 0 && buff[1] === 0)
    buff = buff.slice(1);
  
  if (buff.length > 1 && buff[0] & 0x80 == 0)
    buff = buff.slice(1);
  if (buff[0] & 0x80)
    buff = Buffer.concat([new Buffer([0]), buff]);
  
  if (buff[0] == 0 && buff.length == 1)
    buff = new Buffer(0);
  else  
    buff = new Buffer(buff);
  
  if (neg) {
    var i;
    for (i = 0; i < buff.length; i++)
      buff[i] = ~buff[i];
    
    if (buff[buff.length - 1] == 255) console.log('Fuck twos complement.', buff);
    buff[buff.length - 1]++;
  };
  
  return buff;
};

module.exports = function (data) {
  var len = 0, i, j;
  
  for (i = 0; i < data.length; i++) {
    j = data[i];
    if (j.byte !== undefined || j === true || j === false) len += 1;
    else if (j.uint32 !== undefined) len += 4;
    else if (j.raw) len += j.raw.length;
    else if (Array.isArray(j)) len += 4 + j.join(',').length;
    else if (j.length !== undefined) len += 4 + j.length;
    else if (j.mpint) len += 4 + toTwos(j.mpint).length;
    else console.log('What size is', j);
  };
  
  var payload = new Buffer(len),
      idx = 0;
  
  for (i = 0; i < data.length; i++) {
    j = data[i];
    if (j === true || j === false) j = {byte: (j ? 1 : 0)};
    else if (Array.isArray(j)) j = j.join(',');
    else if (j.mpint) j = toTwos(j.mpint);
    
    if (j.byte !== undefined) payload.writeUInt8(j.byte, (idx += 1) - 1);
    else if (j.uint32 !== undefined) payload.writeUInt32BE(j.uint32, (idx += 4) - 4);
    else if (j.raw) j.raw.copy(payload, (idx += j.raw.length) - j.raw.length);
    else if (j.length !== undefined) {
      if (!Buffer.isBuffer(j)) j = new Buffer(j);
      payload.writeUInt32BE(j.length, idx);
      j.copy(payload, (idx += 4 + j.length) - j.length);
    };
  };
  
  //console.log(data, payload, payload.toString());
  return payload;
};

