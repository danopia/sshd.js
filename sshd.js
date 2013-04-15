var net = require('net'),
    fs = require('fs'),
    crypto = require('crypto'),
    PacketReader = require('./packetreader'),
    composePacket = require('./packetwriter');

var hostkey = fs.readFileSync('/home/danopia/hostkey').toString();
var hostPub = new Buffer(fs.readFileSync('/etc/ssh/ssh_host_rsa_key.pub').toString().split(' ')[1], 'base64');

function signBuffer(buffer) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.write(buffer);
  var signature = signer.sign(hostkey);
  return composePacket(['ssh-rsa', signature]);
}

require('net').createServer(function (conn) {
  var macLen = 0, seqS = 0, seqC = 0, kex, dh, hashIn = [], keyson = false, session, cookie, deciph, cipher, macS, macC, user, proc;
  
  var sendPay = function (payload) {
    var padLen = (16-((5 + payload.length)%16))+16;
    var buffer = new Buffer(5 + payload.length + padLen);
    
    buffer.writeUInt32BE(payload.length + 1 + padLen, 0);
    buffer.writeUInt8(padLen, 4);
    payload.copy(buffer, 5);
    buffer.fill(0, 5 + payload.length);
    
    if (macLen) {
      var asdff = new Buffer(4);
      asdff.writeUInt32BE(seqS, 0);
      var mac = crypto.createHmac('md5', macS.slice(0, 16)); // TODO: net::ssh key_expander.rb
      mac.write(Buffer.concat([asdff,buffer]))
      mac = new Buffer(mac.digest());
    };
    
    console.log('>> Type', payload[0], '-', payload.length, 'bytes');
    if (cipher) buffer = cipher.update(buffer);
    if (macLen) buffer = Buffer.concat([buffer, mac]);
    conn.write(buffer);
    
    seqS += 1;
  };
  
  var sendPayload = function (ast) {
    sendPay(composePacket(ast));
  };
  
  var getPacket = function (packet) {
    var type = packet.getType();
    console.log('<< Type', type, '-', packet.payload.length, 'bytes');
    switch (type) {
      case 1: // disconnect
        var code = packet.readUInt32(),
            msg = packet.readString();
        console.log('Client disconnected:', msg, '('+code+')');
        break;
      
      case 20: // kexinit
        hashIn.push(packet.payload);
        hashIn.push(composePacket([{byte: 20}, {raw: cookie}, ['diffie-hellman-group-exchange-sha256'], ['ssh-rsa'], ['aes256-ctr'], ['aes256-ctr'], ['hmac-md5'], ['hmac-md5'], ['none'], ['none'], [], [], false, {uint32: 0}]));
        hashIn.push(hostPub);
        
        kex = {
          cookie: packet.readBuffer(16),
          kexAlgs:     packet.readList(),
          hostKeyAlgs: packet.readList(),
          encAlgs:    [packet.readList(), packet.readList()],
          macAlgs:    [packet.readList(), packet.readList()],
          cprAlgs:    [packet.readList(), packet.readList()],
          langs:      [packet.readList(), packet.readList()],
          firstKexFollows: packet.readBool()};
        break;
      
      case 34: // SSH_MSG_KEX_DH_GEX_REQUEST
        var dhflags = {
          min: packet.readUInt32(),
          n:   packet.readUInt32(),
          max: packet.readUInt32()};
        hashIn.push({uint32: dhflags.min});
        hashIn.push({uint32: dhflags.n});
        hashIn.push({uint32: dhflags.max});
        dh = require('crypto').getDiffieHellman('modp2');
        
        // SSH_MSG_KEX_DH_GEX_GROUP
        hashIn.push({mpint: dh.getPrime()});
        hashIn.push({mpint: new Buffer([2])});
        sendPay(composePacket([{byte: 31}, {mpint: dh.getPrime()}, {mpint: new Buffer([2])}]));
        dh.generateKeys();
        break;
      
      case 32: // SSH_MSG_KEX_DH_GEX_INIT
        var e = packet.readMpint();
        dh.secret = dh.computeSecret(e);
        
        hashIn.push({mpint: e});
        hashIn.push({mpint: dh.getPublicKey()});
        hashIn.push({mpint: dh.secret});
        
        var sha = require('crypto').createHash('sha256');
        sha.write(composePacket(hashIn));
        session = sha.digest();
        sendPayload([{byte: 33}, hostPub, {mpint: dh.getPublicKey()}, signBuffer(session)]);
        break;
      
      case 21: // SSH_MSG_NEWKEYS okay bro, keys are good, let's goooo
        sendPayload([{byte: 21}]);
        keyson = true;
        
        var keyize = function (salt) {
          // TODO: dh.secret might need ot be encoded for SSH
          var sha = crypto.createHash('SHA256');
          sha.write(Buffer.concat([composePacket([{mpint: dh.secret}]), new Buffer(session), new Buffer(salt), new Buffer(session)]));
          return sha;
        };
        
        //console.log(keyize('C').digest('hex'));
        deciph = crypto.createDecipheriv('aes-256-ctr', keyize('C').digest(), keyize('A').digest().slice(0,16));
        cipher = crypto.createCipheriv  ('aes-256-ctr', keyize('D').digest(), keyize('B').digest().slice(0,16));
        
        macC = keyize('E').digest();
        macS = keyize('F').digest();
        macLen = 16;
        break;
      
      case 5: // SSH_MSG_SERVICE_REQUEST
        var service = packet.readString();
        console.log('Client requested', service);
        if (service == 'ssh-userauth') {
          sendPayload([{byte: 6}, service]); // SSH_MSG_SERVICE_ACCEPT
        } else {
          sendPayload([{byte: 1}, {byte: 0}, 'wtf dude']);
        }
        break;
      
      case 50: // SSH_MSG_USERAUTH_REQUEST
        user = packet.readString();
        var service = packet.readString();
        var method = packet.readString(); // plus more
        console.log(user, service, method);
        sendPayload([{byte: 52}]); // SSH_MSG_USERAUTH_SUCCESS
        break;
      
      case 80: // SSH_MSG_GLOBAL_REQUEST
        var type = packet.readString();
        var wantReply = packet.readBool();
        
        if (type == 'keepalive@openssh.com') {
          console.log('Client is still alive!');
          sendPayload([{byte: 81}]); // SSH_MSG_REQUEST_SUCCESS
        } else {
          console.log('Global requested', type, 'for but idk');
          if (wantReply)
            sendPayload([{byte: 82}]); // SSH_MSG_REQUEST_FAILURE
        };
        break;
      
      case 90: // SSH_MSG_CHANNEL_OPEN
        var channel = {
          type: packet.readString(),
          sender: packet.readUInt32(),
          initSize: packet.readUInt32(),
          maxSize: packet.readUInt32()}; // plus more
        console.log(channel);
          
        sendPayload([{byte: 91}, {uint32: channel.sender}, {uint32: channel.sender}, {uint32: channel.initSize}, {uint32: channel.maxSize}]); // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
        break;
      
      case 96: // SSH_MSG_CHANNEL_EOF
        if (proc) proc.stdin.end();
      case 97: // SSH_MSG_CHANNEL_CLOSE
        break;
      
      case 98: // SSH_MSG_CHANNEL_REQUEST
        var recip = packet.readUInt32();
        var type = packet.readString();
        var wantReply = packet.readBool();
        // plus more
        if (type == 'env') {
          console.log('Environment:', packet.readString(), '=', packet.readString());
        } else if (type == 'exec') {
          var bin = packet.readString();
          console.log('Client wants to exec', bin);
          /*
          if (bin == "git-upload-pack 'sshd.js'") {
            sendPayload([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
            
            proc = require('child_process').spawn('git-upload-pack', ['.git']);
            proc.stdout.on('data', function (d) {
              console.log(d.length, d);
              while (d.length) {
                sendPayload([{byte: 94}, {uint32: recip}, d.slice(0, 50)]);
                d = d.slice(50);
              }
            }).setEncoding('utf8');
            proc.stderr.on('data', function (d) {
              console.log('STDERR:', d);
            }).setEncoding('utf8');
            proc.on('exit', function (code, signal) {
              if (code !== null) {
                sendPayload([{byte: 98}, {uint32: recip}, 'exit-status', false, {uint32: code}]); // SSH_MSG_CHANNEL_REQUEST
              };
              
              sendPayload([{byte: 97}, {uint32: recip}]);
              proc = null;
            });
          } else {
            sendPayload([{byte:100}, {uint32: recip}]); // SSH_MSG_CHANNEL_FAILURE
            break;
          };
          
          /*/
          var cp = require('child_process').spawn('cowsay');
          cp.stdin.write(bin);
          cp.stdin.end();
          cp.stdout.on('data', function (d) {
            console.log(d);
            sendPayload([{byte: 94}, {uint32: recip}, d]);
          }).setEncoding('utf8');
          cp.on('exit', function (code, signal) {
            if (code !== null) {
              sendPayload([{byte: 98}, {uint32: recip}, 'exit-status', false, {uint32: code}]); // SSH_MSG_CHANNEL_REQUEST
            };
            
            sendPayload([{byte: 97}, {uint32: recip}]);
          });
          //*/
        } else if (type == 'pty-req') {
          var pty = {
            term: packet.readString(),
            widthC: packet.readUInt32(),
            heightC: packet.readUInt32(),
            widthP: packet.readUInt32(),
            heightP: packet.readUInt32(),
            modes: packet.readString()};
          
          console.log(wantReply, pty);
          sendPayload([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
        } else if (type == 'shell') {
          console.log('Client warms up their shell');
          sendPayload([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
        } else {
          console.log('Requested', type, 'for', recip, '... but idk');
          if (wantReply)
            sendPayload([{byte: 98}, {uint32: recip}]); // SSH_MSG_CHANNEL_FAILURE
        };
        break;
      
      case 94: // SSH_MSG_CHANNEL_DATA
        var chan = packet.readUInt32();
        var data = packet.readString();
        console.log(chan, data);
        if (proc) {
          while (data.length) {
            proc.stdin.write(data.slice(0, 512));
            data = data.slice(512);
          }
        } else {
          if (data == '\u0004') {
            sendPayload([{byte: 94}, {uint32: chan}, 'Hit q to exit\r\n']);
          } else if (data == 'q') {
            sendPayload([{byte: 98}, {uint32: chan}, 'exit-status', false, {uint32: 0}]); // SSH_MSG_CHANNEL_REQUEST
            sendPayload([{byte: 97}, {uint32: chan}]);
          } else {
            sendPayload([{byte: 94}, {uint32: chan}, 'You hit ' + data + '\r\n']);
          }
        };
        
        break;
      
      default:
        console.log('Unimpl packet', type, packet.payload, packet.payload.toString());
        process.exit();
    };
  };
  
  conn.on('error', function (err) {
    console.log('Connection closed due to error.', err);
  });
  
  console.log('New connection');
  conn.on('data', function (data) {
    if (data.toString('utf-8', 0, 4) === 'SSH-') {
      var eof = data.toString().indexOf('\n');
      console.log('Client header:', data.toString('utf-8', 8, eof-1));
      hashIn.push(data.toString('utf8', 0, eof-1))
      hashIn.push('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS');
      data = data.slice(eof + 1);
    };
    
    while (data.length >= 4) {
      var packet = new PacketReader(data, macLen, deciph, macC, seqC);
      getPacket(packet);
      seqC += 1;
      data = data.slice(packet.totLen);
    };
  });
  
  crypto.randomBytes(16, function (err, rand) {
    conn.write('SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS\r\n');
    
    cookie = rand;
    sendPay(composePacket([{byte: 20}, {raw: cookie}, ['diffie-hellman-group-exchange-sha256'], ['ssh-rsa'], ['aes256-ctr'], ['aes256-ctr'], ['hmac-md5'], ['hmac-md5'], ['none'], ['none'], [], [], false, {uint32: 0}]));
  });
  
}).listen(22);

