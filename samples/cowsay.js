var child_process = require('child_process');

require('./sshd').start(function (session) {
  session.on('channelreq', function (recip, type, wantReply) {
    console.log(type);
    
    if (type == 'exec') {
      var bin = packet.readString();
      console.log('Client wants to exec', bin);
      
      var that = this;
      this.proc = child_process.spawn('cowsay');
      this.proc.stdin.write(bin);
      this.proc.stdin.end();
      this.proc.stdout.on('data', function (d) {
        console.log(d);
        that.sendPay([{byte: 94}, {uint32: recip}, d]);
      }).setEncoding('utf8');
      this.proc.on('error', function (err) {
        console.log('Child process hit an error.', err);
      });
      this.proc.on('exit', function (code, signal) {
        if (code !== null) {
          that.sendPay([{byte: 98}, {uint32: recip}, 'exit-status', false, {uint32: code}]); // SSH_MSG_CHANNEL_REQUEST
        };
        
        that.sendPay([{byte: 97}, {uint32: recip}]);
      });
    } 
  });
});

