# Introduction #

Apparently there's a lil bug in Python 2.5's socket.py that comes to light when using the IMAP mirroring script. Issue tracking at http://bugs.python.org/issue2632

# Details #

http://bugs.python.org/file10032/socket.py.diff

```
Index: socket.py
===================================================================
--- socket.py	(revision 62348)
+++ socket.py	(working copy)
@@ -197,6 +197,7 @@
     """Faux file object attached to a socket object."""
 
     default_bufsize = 8192
+    max_readsize = 65536
     name = "<socket>"
 
     __slots__ = ["mode", "bufsize", "softspace",
@@ -305,7 +306,7 @@
             self._rbuf = ""
             while True:
                 left = size - buf_len
-                recv_size = min(self._rbufsize, left)
+                recv_size = min(self.max_readsize, max(self._rbufsize, left))
                 data = self._sock.recv(recv_size)
                 if not data:
                     break
```