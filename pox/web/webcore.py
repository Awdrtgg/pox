"""
Webcore is a basic web server framework based on the SocketServer-based
BaseHTTPServer that comes with Python.  The big difference is that this
one can carve up URL-space by prefix, such that "/foo/*" gets handled by
a different request handler than "/bar/*".

To support this, at the moment, your request handlers must inherit from
SplitRequestHandler instead of BaseHTTPRequestHandler or whatever.  Work
to support real BaseHTTPRequestHandlers might be almost complete (see
below), but is basically a gross hack.  The interface for 
SplitRequestHandler is basically the same.

BaseHTTPServer is not very fast and needs to run on its own thread.
It'd actually be great to have a version of this written against, say,
CherryPy, but I did want to include a simple one with no dependencies.
"""

from SocketServer import ThreadingMixIn
from BaseHTTPServer import *
from time import sleep
import select
import threading

import random
import hashlib
import base64

from pox.messenger.messenger import MessengerConnection

from pox.core import core

import os
import posixpath
import urllib
import cgi
import shutil
import mimetypes
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

log = core.getLogger()

def _setAttribs (parent, child):
  attrs = ['command', 'request_version', 'close_connection',
           'raw_requestline', 'requestline', 'path', 'headers', 'wfile',
           'rfile', 'server', 'client_address']
  for a in attrs:
    setattr(child, a, getattr(parent, a))

  setattr(child, 'parent', parent)

import SimpleHTTPServer


class SplitRequestHandler (BaseHTTPRequestHandler):
  """
  To write HTTP handlers for POX, inherit from this class instead of
  BaseHTTPRequestHandler.  The interface should be the same -- the same
  variables should be set, and the same do_GET(), etc. methods should
  be called.

  In addition, there will be a self.args which can be specified
  when you set_handler() on the server.
  """
  # Also a StreamRequestHandler

  def __init__ (self, parent, prefix, args):
    _setAttribs(parent, self)

    self.parent = parent
    self.args = args
    self.prefix = prefix

    self._init()

  def _init (self):
    """
    This is called by __init__ during initialization.  You can
    override it to, for example, parse .args.
    """
    pass

  def handle_one_request (self):
    raise RuntimeError("Not supported")

  def handle(self):
    raise RuntimeError("Not supported")

  def log_request (self, code = '-', size = '-'):
    log.debug(self.prefix + (':"%s" %s %s' % 
              (self.requestline, str(code), str(size))))

  def log_error (self, fmt, *args):
    log.error(self.prefix + ':' + (fmt % args))

  def log_message (self, fmt, *args):
    log.info(self.prefix + ':' + (fmt % args))


class CoreHandler (SplitRequestHandler):
  """
  A default page to say hi from POX.
  """
  def do_GET (self):
    """Serve a GET request."""
    self.send_info(True)

  def do_HEAD (self):
    """Serve a HEAD request."""
    self.self_info(False)

  def send_info (self, isGet = False):
    r = "<html><head><title>POX</title></head>\n"
    r += "<body>\n<h1>POX Webserver</h1>\n<h2>Components</h2>\n"
    r += "<ul>"
    for k in sorted(core.components):
      v = core.components[k]
      r += "<li>%s - %s</li>\n" % (cgi.escape(str(k)), cgi.escape(str(v)))
    r += "</ul>\n\n<h2>Web Prefixes</h2>"
    r += "<ul>"
    m = [map(cgi.escape, map(str, [x[0],x[1],x[3]]))
         for x in self.args.matches]
    m.sort()
    for v in m:
      r += "<li>%s - %s %s</li>\n" % tuple(v)
    r += "</ul></body></html>\n"

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    if isGet:
      self.wfile.write(r)


class StaticContentHandler (SplitRequestHandler):
    # This is basically SimpleHTTPRequestHandler from Python, but
    # modified to serve from given directories and to inherit from
    # SplitRequestHandler.

    """Simple HTTP request handler with GET and HEAD commands.

    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.

    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.

    """

    server_version = "StaticContentHandler/1.0"

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def send_head(self):
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.prefix + self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may
            # cause newline translations, making the actual size of the
            # content transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified",self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = StringIO()
        displaypath = cgi.escape(urllib.unquote(self.path))
        f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write("<html>\n<title>Directory listing for %s</title>\n" %
                displaypath)
        f.write("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
        f.write("<hr>\n<ul>\n")
        f.write('<li><a href=".."><i>Parent Directory</i></a>\n')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # a link to a directory displays with @ and links with /
            f.write('<li><a href="%s">%s</a>\n'
                    % (urllib.quote(linkname), cgi.escape(displayname)))
        f.write("</ul>\n<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        #path = os.getcwd()
        path = os.path.abspath(self.args['root'])
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.

        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).

        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.

        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.

        Argument is a PATH (a filename).

        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.

        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.

        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })


#NOTE: This is incomplete work towards being able to support handlers
#      written directly against BaseHTTPRequestHandler.
#      (The next step is to monkeypatch the handle or handle_one_request
#      in the user-supplied handler class to call the one in the split
#      request handler instead.
#
#class Recorder (object):
#  def __init__(self, parent, sock, mode, bufsize):
#    self.sock = sock
#    self.reader = sock.makefile(mode, bufsize)
#    self.parent = parent
#
#  def readline (self):
#    print "READLINE"
#    b = self.reader.readline()
#    self.parent.buf += b
#    return b
#
#  def read (self, n = None):
#    print "READ"
#    if n is None: # Not sure what default value is
#      b = self.reader.read()
#    else:
#      b = sock.reader.read(n)
#    self.parent.buf += b
#
#  def __getattr__(self, n):
#    print "Recorder",n
#    return getattr(self.reader, n)
#
#class Player (object):
#  def __init__(self, parent, sock, mode, bufsize):
#    self.sock = sock
#    self.reader = sock.makefile(mode, bufsize)
#    self.parent = parent
#
#  def readline (self):
#    print "PLAYER READLINE"
#    if len(self.parent.buf):
#      l = self.parent.buf.find("\n")
#      if l == -1:
#        r = self.parent.buf
#        self.parent.buf = b''
#        return r
#      r = self.parent.buf[0:l]
#      self.parent.buf = self.parent.buf[l+1:]
#      return r
#    b = self.reader.readline()
#    self.parent.buf += b
#    return b
#
#  def unread (self, stuff):
#    print "player unread", stuff
#    self.parent.buf = stuff + self.parent.buf
#
#  def read (self, n=None):
#    if n is None:
#      r = self.parent.buf
#      self.parent.buf = b''
#      return r + self.reader.read()
#    
#    if n <= len(self.parent.buf):
#      r = self.parent.buf[0:n]
#      self.parent.buf = self.parent.buf[n:]
#      return r
#
#    additional = n - len(self.parent.buf)
#    r = self.parent.buf
#    self.parent.buf = b''
#
#    return r + self.reader.read(additional)
#      
#  def __getattr__(self, n):
#    print "Player",n
#    return getattr(self.reader, n)
#
#
#class Playback (object):
#  def __init__ (self, recording, sock):
#    self.sock = sock
#    self.rec = recording
#    self.buf = recording.buf
#
#  def makefile (self, mode='r', bufsize=-1):
#    if 'w' in mode:
#      return self.sock.makefile(mode, bufsize)
#    else:
#      print self, self.sock,mode,bufsize,"<<"
#      return Player(self, self.sock, mode, bufsize)
#    
#
#class Recording (object):
#  def __init__ (self, sock):
#    self.sock = sock
#    self.buf = b''
#
#  def makefile (self, mode='r', bufsize=-1):
#    print "makefile",mode,bufsize
#    if 'w' in mode:
#      return self.sock.makefile(mode, bufsize)
#    else:
#      return Recorder(self, self.sock, mode, bufsize)
#
#  def getPlayback (self):
#    return Playback(self, self.sock)

class SplitterRequestHandler (BaseHTTPRequestHandler):
  def __init__ (self, *args, **kw):
    #self.rec = Recording(args[0])
    #self.args = args
    #self.matches = self.matches.sort(key=lambda e:len(e[0]),reverse=True)
    #BaseHTTPRequestHandler.__init__(self, self.rec, *args[1:], **kw)
    BaseHTTPRequestHandler.__init__(self, *args, **kw)

  def log_request (self, code = '-', size = '-'):
    log.debug('splitter:"%s" %s %s',
              self.requestline, str(code), str(size))

  def log_error (self, fmt, *args):
    log.error('splitter:' + fmt % args)

  def log_message (self, fmt, *args):
    log.info('splitter:' + fmt % args)

  def handle_one_request(self):
    self.raw_requestline = self.rfile.readline()
    if not self.raw_requestline:
        self.close_connection = 1
        return
    if not self.parse_request(): # An error code has been sent, just exit
        return
    
    handler = None

    while True:
      for m in self.server.matches:
        if self.path.startswith(m[0]):
          #print m,self.path
          handler = m[1](self, m[0], m[3])
          #pb = self.rec.getPlayback()
          #handler = m[1](pb, *self.args[1:])
          _setAttribs(self, handler)
          if m[2]:
            # Trim. Behavior is not "perfect"
            handler.path = self.path[len(m[0]):]
            if m[0].endswith('/'):
              handler.path = '/' + handler.path
          break

      if handler is None:
        handler = self
        if not self.path.endswith('/'):
          # redirect browser - doing basically what apache does
          self.send_response(301)
          print "redirect to ",self.path+'/'
          self.send_header("Location", self.path + "/")
          self.end_headers()
          continue

      break

    mname = 'do_' + self.command
    if not hasattr(handler, mname):
        self.send_error(501, "Unsupported method (%r)" % self.command)
        return
    method = getattr(handler, mname)
    return method()



class SplitThreadedServer(ThreadingMixIn, HTTPServer):
  matches = [] # Tuples of (Prefix, TrimPrefix, Handler)

#  def __init__ (self, *args, **kw):
#    BaseHTTPRequestHandler.__init__(self, *args, **kw)
#    self.matches = self.matches.sort(key=lambda e:len(e[0]),reverse=True)

  def set_handler (self, prefix, handler, args = None, trim_prefix = True):
    # Not very efficient
    assert (handler is None) or (issubclass(handler, SplitRequestHandler))
    self.matches = [m for m in self.matches if m[0] != prefix]
    if handler is None: return
    self.matches.append((prefix, handler, trim_prefix, args))
    self.matches.sort(key=lambda e:len(e[0]),reverse=True)



def launch (address='', port=8000, debug=False, static=False):
  if debug:
    log.setLevel("DEBUG")
    log.debug("Debugging enabled")

  httpd = SplitThreadedServer((address, int(port)), SplitterRequestHandler)
  core.register("WebServer", httpd)
  httpd.set_handler("/", CoreHandler, httpd, True)
  #httpd.set_handler("/foo", StaticContentHandler, {'root':'.'}, True)
  #httpd.set_handler("/f", StaticContentHandler, {'root':'pox'}, True)
  if static:
    import os
    path = os.path.dirname(os.path.abspath( __file__ ))
    path = os.path.join(path, 'www_root')
    print "static on ",path
    httpd.set_handler("/static", StaticContentHandler, {'root':path}, True)


  def run ():
    try:
      httpd.serve_forever()
    except:
      pass
    log.info("Server quit")

  thread = threading.Thread(target=run)
  thread.daemon = True
  thread.start()

