var net = require('net'),
    fs = require('fs'),
    crypto = require('crypto'),
    util = require('util'),
    events = require('events'),
    PacketReader = require('./packetreader'),
    composePacket = require('./packetwriter');

var hostkey = fs.readFileSync('rsa_host_key').toString();
var hostPub = new Buffer(fs.readFileSync('rsa_host_key.pub').toString().split(' ')[1], 'base64');

var Session = function (conn) {
  this.macLen = 0;
  this.seqS = 0;
  this.seqC = 0;
  this.hashIn = [];
  this.keys = [];
  
  this.conn = conn;
  
  var that = this;
  
  conn.on('error', function (err) {
    console.log('Connection closed due to error.', err);
  });
  conn.on('close', function (err) {
    console.log('Connection closed.');
    if (that.proc) that.proc.kill();
  });
  
  conn.on('data', function (data) {
    if (data.toString('utf-8', 0, 4) === 'SSH-') {
      var eof = data.toString().indexOf('\n');
      console.log('Client header:', data.toString('utf-8', 8, eof-1));
      that.hashIn.push(data.toString('utf8', 0, eof-1))
      that.hashIn.push('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS');
      data = data.slice(eof + 1);
    };
    
    while (data.length >= 4) {
      var packet = new PacketReader(data, that.macLen, that.deciph, that.macC, that.seqC);
      that.getPacket(packet);
      that.seqC += 1;
      data = data.slice(packet.totLen);
    };
  });
  
  crypto.randomBytes(16, function (err, rand) {
    that.conn.write('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS\r\n');
    
    that.cookie = rand;
    that.sendPay([{byte: 20}, {raw: that.cookie}, ['diffie-hellman-group-exchange-sha256'], ['ssh-rsa'], ['aes256-ctr'], ['aes256-ctr'], ['hmac-md5'], ['hmac-md5'], ['none'], ['none'], [], [], false, {uint32: 0}]);
  });
};
util.inherits(Session, events.EventEmitter);

Session.prototype.signBuffer = function (buffer) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.write(buffer);
  var signature = signer.sign(hostkey);
  return composePacket(['ssh-rsa', signature]);
};

Session.prototype.sendPay = function (ast) {
  var payload = composePacket(ast);
  
  var padLen = (16-((5 + payload.length)%16))+16;
  var buffer = new Buffer(5 + payload.length + padLen);
  
  buffer.writeUInt32BE(payload.length + 1 + padLen, 0);
  buffer.writeUInt8(padLen, 4);
  payload.copy(buffer, 5);
  buffer.fill(0, 5 + payload.length);
  
  if (this.macLen) {
    var asdff = new Buffer(4);
    asdff.writeUInt32BE(this.seqS, 0);
    var mac = crypto.createHmac('md5', this.macS.slice(0, 16)); // TODO: net::ssh key_expander.rb
    mac.write(Buffer.concat([asdff, buffer]))
    mac = new Buffer(mac.digest());
  };
  
  console.log('>> Type', payload[0], '-', payload.length, 'bytes');
  if (this.cipher) buffer = this.cipher.update(buffer);
  if (this.macLen) buffer = Buffer.concat([buffer, mac]);
  this.conn.write(buffer);
  
  this.seqS += 1;
};

Session.prototype.keyize = function (salt) {
  var sha = crypto.createHash('SHA256');
  sha.write(Buffer.concat([composePacket([{mpint: this.dh.secret}]), new Buffer(this.session), new Buffer(salt), new Buffer(this.session)]));
  return sha;
};

Session.prototype.getPacket = function (packet) {
  var type = packet.getType();
  console.log('<< Type', type, '-', packet.payload.length, 'bytes');
  switch (type) {
    case 1: // disconnect
      var code = packet.readUInt32(),
          msg = packet.readString();
      console.log('Client disconnected:', msg, '('+code+')');
      break;
    
    case 20: // kexinit
      this.hashIn.push(packet.payload);
      this.hashIn.push(composePacket([{byte: 20}, {raw: this.cookie}, ['diffie-hellman-group-exchange-sha256'], ['ssh-rsa'], ['aes256-ctr'], ['aes256-ctr'], ['hmac-md5'], ['hmac-md5'], ['none'], ['none'], [], [], false, {uint32: 0}]));
      this.hashIn.push(hostPub);
      
      this.kex = {
        cookie: packet.readBuffer(16),
        kexAlgs:     packet.readList(),
        hostKeyAlgs: packet.readList(),
        encAlgs:    [packet.readList(), packet.readList()],
        macAlgs:    [packet.readList(), packet.readList()],
        cprAlgs:    [packet.readList(), packet.readList()],
        langs:      [packet.readList(), packet.readList()],
        firstKexFollows: packet.readBool()};
      break;
    
    case 30: // older 34
      this.dhflags = { n:   packet.readUInt32() };
      this.hashIn.push({uint32: this.dhflags.n});
      this.dh = crypto.getDiffieHellman('modp2');
      
      // SSH_MSG_KEX_DH_GEX_GROUP
      this.hashIn.push({mpint: this.dh.getPrime()});
      this.hashIn.push({mpint: new Buffer([2])});
      this.sendPay([{byte: 31}, {mpint: this.dh.getPrime()}, {mpint: new Buffer([2])}]);
      this.dh.generateKeys();
      break;
    
    case 34: // SSH_MSG_KEX_DH_GEX_REQUEST
      this.dhflags = {
        min: packet.readUInt32(),
        n:   packet.readUInt32(),
        max: packet.readUInt32()};
      this.hashIn.push({uint32: this.dhflags.min});
      this.hashIn.push({uint32: this.dhflags.n});
      this.hashIn.push({uint32: this.dhflags.max});
      this.dh = crypto.getDiffieHellman('modp2');
      
      // SSH_MSG_KEX_DH_GEX_GROUP
      this.hashIn.push({mpint: this.dh.getPrime()});
      this.hashIn.push({mpint: new Buffer([2])});
      this.sendPay([{byte: 31}, {mpint: this.dh.getPrime()}, {mpint: new Buffer([2])}]);
      this.dh.generateKeys();
      break;
    
    case 32: // SSH_MSG_KEX_DH_GEX_INIT
      this.e = packet.readMpint();
      this.dh.secret = this.dh.computeSecret(this.e);
      
      this.hashIn.push({mpint: this.e});
      this.hashIn.push({mpint: this.dh.getPublicKey()});
      this.hashIn.push({mpint: this.dh.secret});
      
      var sha = crypto.createHash('sha256');
      sha.write(composePacket(this.hashIn));
      this.session = sha.digest();
      this.sendPay([{byte: 33}, hostPub, {mpint: this.dh.getPublicKey()}, this.signBuffer(this.session)]);
      break;
    
    case 21: // SSH_MSG_NEWKEYS okay bro, keys are good, let's goooo
      this.sendPay([{byte: 21}]);
      this.keyson = true;
      
      //console.log(keyize('C').digest('hex'));
      this.deciph = crypto.createDecipheriv('aes-256-ctr', this.keyize('C').digest(), this.keyize('A').digest().slice(0,16));
      this.cipher = crypto.createCipheriv  ('aes-256-ctr', this.keyize('D').digest(), this.keyize('B').digest().slice(0,16));
      
      this.macC = this.keyize('E').digest();
      this.macS = this.keyize('F').digest();
      this.macLen = 16;
      break;
    
    case 5: // SSH_MSG_SERVICE_REQUEST
      var service = packet.readString();
      console.log('Client requested', service);
      if (service == 'ssh-userauth') {
        this.sendPay([{byte: 6}, service]); // SSH_MSG_SERVICE_ACCEPT
      } else {
        this.sendPay([{byte: 1}, {byte: 0}, 'wtf dude']);
      }
      break;
    
    case 50: // SSH_MSG_USERAUTH_REQUEST
      this.user = packet.readString();
      var service = packet.readString();
      var method = packet.readString(); // plus more
      console.log(this.user, service, method);
      if (method == 'none') {
        if (true) { // anonymous server?
          this.sendPay([{byte: 52}]); // SSH_MSG_USERAUTH_SUCCESS
        } else {
          this.sendPay([{byte: 51}, ['publickey', 'keyboard-interactive'], false]); // SSH_MSG_USERAUTH_FAILURE
        };
      } else if (method == 'keyboard-interactive') {
        var lang = packet.readString();
        var submethods = packet.readString();
        console.log({lang:lang,submethods:submethods});
        if (this.keys.length) {
          this.sendPay([{byte: 60}, 'Log in to Gitbus', "Your "+this.keys.length+" public keys were not recognized by gitbus. If you'd like to add one, please log in.", 'en-US', {uint32:2}, 'Username: ', true, 'Password: ', false]); // SSH_MSG_USERAUTH_INFO_REQUEST
        } else {
          this.sendPay([{byte: 51}, ['publickey'], false]); // SSH_MSG_USERAUTH_FAILURE
        }
      } else if (method == 'password') {
        this.sendPay([{byte: 53}, 'Welcome to Gitbus!\r\n', 'en-US']);
        this.sendPay([{byte: 53}, "I don't recognize your SSH public key.\r\n", 'en-US']);
        this.sendPay([{byte: 53}, "If you'd like to pair it to " + user + ", enter your gitbus password now.\r\n", 'en-US']);
      } else if (method == 'publickey') {
        var signed = packet.readBool();
        var key = {
          alg: packet.readString(),
          blob: packet.readString()};
        console.log(key);
        this.keys.push(key);
        this.sendPay([{byte: 51}, ['publickey', 'keyboard-interactive'], false]); // SSH_MSG_USERAUTH_FAILURE
      } else {
        this.sendPay([{byte: 51}, ['publickey', 'keyboard-interactive', 'password'], false]); // SSH_MSG_USERAUTH_FAILURE
      };
      break;
    
    case 61: // SSH_MSG_USERAUTH_INFO_RESPONSE
      var count = packet.readUInt32();
      if (this.stage) {
//          var keynum = packet.readString();
//          var comment = packet.readString();
        this.sendPay([{byte: 53}, 'Key successfully added.\r\n', 'en-US']);
        this.sendPay([{byte: 52}]); // SSH_MSG_USERAUTH_INFO_REQUEST
      } else {
        var username = packet.readString();
        var password = packet.readString();
        if (keys.length > 1) {
          this.sendPay([{byte: 60}, 'Select public key to add', keys.map(function(key,i){return ''+i+': '+key.alg+' '+(new Buffer(key.blob).toString('base64')).slice(0,60)+'...'}).join('\r\n'), 'en-US', {uint32:2}, 'Key number: ', true, 'Key label/comment: ', true]); // SSH_MSG_USERAUTH_INFO_REQUEST
        } else {
          this.sendPay([{byte: 60}, 'Add key to Gitbus', keys[0].alg+' '+(new Buffer(keys[0].blob).toString('base64')).slice(0,60)+'... will be added to your Gitbus.', 'en-US', {uint32:1}, 'Key label/comment: ', true]); // SSH_MSG_USERAUTH_INFO_REQUEST
        };
        this.stage = true;
      };
      break;
    
    case 80: // SSH_MSG_GLOBAL_REQUEST
      var type = packet.readString();
      var wantReply = packet.readBool();
      
      if (type == 'keepalive@openssh.com') {
        console.log('Client is still alive!');
        this.sendPay([{byte: 81}]); // SSH_MSG_REQUEST_SUCCESS
      } else {
        console.log('Global requested', type, 'for but idk');
        if (wantReply)
          this.sendPay([{byte: 82}]); // SSH_MSG_REQUEST_FAILURE
      };
      break;
    
    case 90: // SSH_MSG_CHANNEL_OPEN
      var channel = {
        type: packet.readString(),
        sender: packet.readUInt32(),
        initSize: packet.readUInt32(),
        maxSize: packet.readUInt32()}; // plus more
      console.log(channel);
        
      this.sendPay([{byte: 91}, {uint32: channel.sender}, {uint32: channel.sender}, {uint32: channel.initSize}, {uint32: channel.maxSize}]); // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
      break;
    
    case 96: // SSH_MSG_CHANNEL_EOF
      if (this.proc) proc.stdin.end();
    case 97: // SSH_MSG_CHANNEL_CLOSE
      break;
    
    case 98: // SSH_MSG_CHANNEL_REQUEST
      var recip = packet.readUInt32();
      var type = packet.readString();
      var wantReply = packet.readBool();
      // plus more
      
      if (this.emit('channelreq', recip, type, wantReply)) {
        // handled
      } else if (type == 'env') {
        console.log('Environment:', packet.readString(), '=', packet.readString());
      } else if (type == 'pty-req') {
        var pty = {
          term: packet.readString(),
          widthC: packet.readUInt32(),
          heightC: packet.readUInt32(),
          widthP: packet.readUInt32(),
          heightP: packet.readUInt32(),
          modes: packet.readString()};
        
        console.log(wantReply, pty);
        this.sendPay([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
      } else {
        console.log('Requested', type, 'for', recip, '... but idk');
        if (wantReply)
          that.sendPay([{byte: 98}, {uint32: recip}]); // SSH_MSG_CHANNEL_FAILURE
      };
      break;
    
    case 93: // SSH_MSG_CHANNEL_WINDOW_ADJUST
      break;
    
    case 94: // SSH_MSG_CHANNEL_DATA
      var chan = packet.readUInt32();
      var data = packet.readString();
      console.log(chan, data);
      if (this.proc) {
        if (data == '\u0003' || data == 'q') {
          this.proc.kill('SIGINT');
          this.proc = null;
        } else {
          while (data.length) {
            this.proc.stdin.write(data.slice(0, 512));
            data = data.slice(512);
          };
        };
      } else {
        if (data == '\u0004') {
          this.sendPay([{byte: 94}, {uint32: chan}, 'Hit q to exit\r\n']);
        } else if (data == 'q') {
          this.sendPay([{byte: 98}, {uint32: chan}, 'exit-status', false, {uint32: 0}]); // SSH_MSG_CHANNEL_REQUEST
          this.sendPay([{byte: 97}, {uint32: chan}]);
        } else {
          this.sendPay([{byte: 94}, {uint32: chan}, 'You hit ' + data + '\r\n']);
        }
      };
      
      break;
    
    default:
      console.log('Unimpl packet', type, packet.payload, packet.payload.toString());
      process.exit();
  };
};

exports.start = function (callback) {
  net.createServer(function (conn) {
    console.log('New connection');
    
    var sess = new Session(conn);
    callback(sess);
  }).listen(22);
};

