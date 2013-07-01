var child_process = require('child_process');

require('./sshd').start(function (session) {
  session.on('channelreq', function (recip, type, wantReply) {
    console.log(type);
    
    if (type == 'exec') {
      var bin = packet.readString();
      console.log('Client wants to exec', bin);
      
      if (bin == "git-upload-pack 'sshd.js'") {
        sendPay([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
        
        proc = require('child_process').spawn('git-upload-pack', ['.git']);
        proc.stdout.on('data', function (d) {
          console.log(d.length, d);
          while (d.length) {
            sendPay([{byte: 94}, {uint32: recip}, d.slice(0, 50)]);
            d = d.slice(50);
          }
        }).setEncoding('utf8');
        proc.stderr.on('data', function (d) {
          console.log('STDERR:', d);
        }).setEncoding('utf8');
        proc.on('exit', function (code, signal) {
          if (code !== null) {
            sendPay([{byte: 98}, {uint32: recip}, 'exit-status', false, {uint32: code}]); // SSH_MSG_CHANNEL_REQUEST
          };
          
          sendPay([{byte: 97}, {uint32: recip}]);
          proc = null;
        });
      } else {
        sendPay([{byte:100}, {uint32: recip}]); // SSH_MSG_CHANNEL_FAILURE
        break;
      };
    }
  });
});

