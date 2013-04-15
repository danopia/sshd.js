sshd.js
=======

Secure Shell server written in Javascript using only the NodeJS standard library.

Currently only supports Diffie-Huffman SHA256, which most desktop SSH clients support. Mobile
clients appear to only implement the SHA1 version, which will be supported soon.

Until the code has been refactored, it is not exactly clean or well-organized, so don't
complain too much about it :) I plan to completely redo it soon, with a few more classes and
a bit more eventing.

HEAD is currently set up to pass you through to a `nyancat` binary, with no authentication,
and for any username.

Goal
----
The goal of the project is to make a library for people to easily create special-purpose SSHds,
essentially as easily as special-purpose telnet servers are. The original inspiration for
starting this project was for a planned git hosting service.
