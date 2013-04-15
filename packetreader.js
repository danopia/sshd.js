var PacketReader = module.exports = function (buffer, macLen, deciph, macC, seqC) {
  var d1 = deciph ? deciph.update(buffer.slice(0, 5)) : buffer;
  var pktLen = d1.readUInt32BE(0),
      padLen = d1.readUInt8(4),
      payLen = pktLen - padLen,
      macIdx = 4 + pktLen;
  
  this.totLen = 4 + pktLen + macLen;
  this.orig   = buffer.slice(5, 4 + payLen);
  this.mac    = buffer.slice(macIdx, macIdx + macLen);
  
  this.payload = deciph ? deciph.update(this.orig) : this.orig;
  if (buffer.slice(4 + payLen, 4 + payLen + padLen).length != padLen) {
    console.log(d1);
  };
  if (deciph) this.padding = deciph.update(buffer.slice(4 + payLen, 4 + payLen + padLen));
  
  if (macLen) {
    var asdff = new Buffer(4);
    asdff.writeUInt32BE(seqC, 0);
    var mac = require('crypto').createHmac('md5', macC.slice(0, 16)); // TODO: net::ssh key_expander.rb
    mac.write(Buffer.concat([asdff,d1,this.payload,this.padding]))
    mac = new Buffer(mac.digest());
    if (mac.toString() != this.mac.toString()) console.log('SECURITY ERROR: MAC hash from client is incorrect');
  };
  
  this.idx = 1;
};

PacketReader.prototype = {
  getType: function () {
    return this.payload.readUInt8(0);
  },
  
  readUInt8: function () {
    return this.payload.readUInt8((this.idx += 1) - 1);
  },
  
  readUInt32: function () {
    return this.payload.readUInt32BE((this.idx += 4) - 4);
  },
  
  readBool: function () {
    return this.readUInt8() > 0;
  },
  
  readBuffer: function (len) {
    if (!len) len = this.readUInt32();
    return this.payload.slice(this.idx, this.idx += len);
  },
  
  readString: function (len) {
    if (!len) len = this.readUInt32();
    return this.payload.toString('utf8', this.idx, this.idx += len);
  },
  
  readList: function () {
    var str = this.readString();
    return (str.length ? str.split(',') : []);
  },
  
  readMpint: function () {
    var buff = this.readBuffer();
    if (buff[0] & 0x80) {
      console.log('Really, fuck twos complement.', buff);
    } else {
      if (buff[0] == 0) buff = buff.slice(1);
      return buff;
    };
  },
};

