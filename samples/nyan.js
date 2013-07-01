var child_process = require('child_process');

require('./sshd').start(function (session) {
  session.on('channelreq', function (recip, type, wantReply) {
    console.log(type);
    
    if (type == 'shell') {
      console.log('Client warms up their shell');
      this.sendPay([{byte: 99}, {uint32: recip}]); // SSH_MSG_CHANNEL_SUCCESS
      
      var that = this;
      this.sendPay([{byte: 94}, {uint32: recip}, "\x1B[48;5;17m"]);
      this.proc = child_process.spawn('nyancat');
      this.proc.stdout.on('data', function (d) {
        that.sendPay([{byte: 94}, {uint32: recip}, d.replace(/\n/g, '\r\n')]);
      }).setEncoding('utf8');
      this.proc.on('exit', function (code, signal) {
        if (code !== null) {
          that.sendPay([{byte: 98}, {uint32: recip}, 'exit-status', false, {uint32: code}]); // SSH_MSG_CHANNEL_REQUEST
        };
        
        that.sendPay([{byte: 97}, {uint32: recip}]);
      });
      this.proc.on('error', function (err) {
        console.log('Child process hit an error.', err);
      });
    }
  });
});

