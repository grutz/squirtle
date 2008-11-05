#!/usr/bin/env python
 
"""IMAP Incremental Backup Script"""
__version__ = "1.4a-squirtle"
__author__ = "Rui Carmo (http://the.taoofmac.com)"
__copyright__ = "(C) 2006 Rui Carmo. Code under BSD License.\n(C)"
__contributors__ = "Bob Ippolito, Michael Leonhard, Giuseppe Scrivano <gscrivano@gnu.org>, Kurt Grutzmacher <grutz@jingojango.net>"
 
# = Contributors =
# Giuseppe Scrivano: Added support for folders.
# Michael Leonhard: LIST result parsing, SSL support, revamped argument processing,
#                   moved spinner into class, extended recv fix to Windows
# Bob Ippolito: fix for MemoryError on socket recv, http://python.org/sf/1092502
# Rui Carmo: original author, up to v1.2e
# Kurt Grutzmacher: Squirtle support, use Maildir instead of mbox
 
# = TODO =
# - Add proper exception handlers to scanFile() and downloadMessages()
# - Migrate mailbox usage from rfc822 module to email module
# - Investigate using the noseek mailbox/email option to improve speed
# - Use the email module to normalize downloaded messages
#   and add missing Message-Id
# - Test parseList() and its descendents on other imapds
# - Test bzip2 support
# - Add option to download only subscribed folders
# - Add regex option to filter folders
# - Use a single IMAP command to get Message-IDs
# - Use a single IMAP command to fetch the messages
# - Add option to turn off spinner.  Since sys.stdin.isatty() doesn't work on
#   Windows, redirecting output to a file results in junk output.
# - Patch Python's ssl module to do proper checking of certificate chain
# - Patch Python's ssl module to raise good exceptions
# - Submit patch of socket._fileobject.read
# - Improve imaplib module with LIST parsing code, submit patch
# DONE:
# v1.3c
# - Add SSL support
# - Support host:port
# - Cleaned up code using PyLint to identify problems
#   pylint -f html --indent-string="  " --max-line-length=90 imapbackup.py > report.html
import getpass, os, gc, sys, time, platform, getopt
import mailbox, imaplib, socket
import re, sha, gzip, bz2
import urllib, urllib2, simplejson
    
class SkipFolderException(Exception):
  """Indicates aborting processing of current folder, continue with next folder."""
  pass
 
class Spinner:
  """Prints out message with cute spinner, indicating progress"""
 
  def __init__(self, message):
    """Spinner constructor"""
    self.glyphs = "|/-\\"
    self.pos = 0
    self.message = message
    sys.stdout.write(message)
    sys.stdout.flush()
    self.spin()
 
  def spin(self):
    """Rotate the spinner"""
    if sys.stdin.isatty():
      sys.stdout.write("\r" + self.message + " " + self.glyphs[self.pos])
      sys.stdout.flush()
      self.pos = (self.pos+1) % len(self.glyphs)
 
  def stop(self):
    """Erase the spinner from the screen"""
    if sys.stdin.isatty():
      sys.stdout.write("\r" + self.message + "  ")
      sys.stdout.write("\r" + self.message)
      sys.stdout.flush()
 
def pretty_byte_count(num):
  """Converts integer into a human friendly count of bytes, eg: 12.243 MB"""
  if num == 1:
    return "1 byte"
  elif num < 1024:
    return "%s bytes" % (num)
  elif num < 1048576:
    return "%.2f KB" % (num/1024.0)
  elif num < 1073741824:
    return "%.3f MB" % (num/1048576.0)
  elif num < 1099511627776:
    return "%.3f GB" % (num/1073741824.0)
  else:
    return "%.3f TB" % (num/1099511627776.0)
 
 
# Regular expressions for parsing
MSGID_RE = re.compile("^Message\-Id\: (.+)", re.IGNORECASE + re.MULTILINE)
BLANKS_RE = re.compile(r'\s+', re.MULTILINE)
 
# Constants
UUID = '19AF1258-1AAF-44EF-9D9A-731079D6FAD7' # Used to generate Message-Ids

def process_type2(msg2, sqkey='', squri="http://localhost:8080/", squser="squirtle", sqpass="eltriuqs"):
  msg2 = urllib.quote(msg2)
  auth_handler = urllib2.HTTPBasicAuthHandler()
  auth_handler.add_password(realm='Squirtle Realm',
                            uri=squri,
                            user=squser,
                            passwd=sqpass)
  urlopener = urllib2.build_opener(auth_handler)
  urllib2.install_opener(urlopener)

  dutchieurl = "%scontroller/type2?key=%s&type2=%s" % (squri, sqkey, msg2)
  try:
    res = urllib2.urlopen(dutchieurl)
  except urllib2.URLError, e:
    print '*** Error talking to Squirtle.' + str(e.code) + ': ' + e.reason + '\n'
    return ''

  response = res.read()
  try:
    response = simplejson.loads(response)
  except Exception, e:
    print '*** Error receiving response from Squirtle: ' + response + '\n'
    return ''

  if response['status'] == 'ok':
    NTLM_msg3 = response['result']
  else:
    print '*** Response from Squirtle: ' + response['status'] + '\n'

  return NTLM_msg3

def login_squirtle(server, sqkey):
  """Login as a user using the Squirtle API"""

  typ, dat = server.capability()
  if not "NTLM" in str(dat):
    raise self.error("!!! IMAP server does not support NTLM !!!")

  server.send("0001 AUTHENTICATE NTLM\r\n")
  dat = server.readline()
  if "+" not in dat:
    raise server.error("!!! Did not receive IMAP challenge: %s" % (dat))

  # generic ntlm type 1 message
  server.send("TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==\r\n")
  dat = server.readline()
  if "+" not in dat:
    raise server.error("!!! Invalid response: %s" % (dat))

  msg3 = process_type2(dat[2:].strip(), sqkey, "http://localhost:8080/", "squirtle", "eltriuqs")
  if len(msg3) > 0:
    server.send("%s\r\n" % msg3)
    dat = server.readline()
    if "0001 OK" not in dat:
      raise server.error("!!! Did not receive OK message: %s" % (dat))

    server.state = 'AUTH'
  else:
    raise server.error("!!! No response from Squirtle")
  return

def download_messages(server, mpath, foldername, messages, config):
  """Download messages from folder and append to maildr folder"""
 
  # nothing to do
  if not len(messages):
    print "New messages: 0"
    return

  mbox = mailbox.Maildir(mpath)
  try:
    mbox = mbox.get_folder(foldername)
  except NoSuchMailboxError, e:
    mbox = mbox.add_folder(foldername)
 
  spinner = Spinner("Downloading %s new messages to %s" % (len(messages), foldername))
  total = biggest = 0
 
  # each new message
  for msg_id in messages.keys():
    # fetch message
    typ, data = server.fetch(messages[msg_id], "RFC822")
    assert('OK' == typ)
    text = data[0][1].strip().replace('\r','')
    mbox.add(text)
 
    size = len(text)
    biggest = max(size, biggest)
    total += size
 
    del data
    gc.collect()
    spinner.spin()
 
  mbox.clean()
  mbox.close()
  spinner.stop()
  print ": %s total, %s for largest message" % (pretty_byte_count(total),
                                                pretty_byte_count(biggest))
 
def scan_file(mpath, foldername, compress, overwrite):
  """Gets IDs of messages in the specified maildir folder"""

  spinner = Spinner("File %s" % (foldername))
 
  mbox = mailbox.Maildir(mpath)
  try:
    mbox = mbox.get_folder(foldername)
  except mailbox.NoSuchMailboxError:
    mbox = mbox.add_folder(foldername)

  messages = {}
 
  # each message
  i = 0
  for message in mbox:
    header = ''
    # We assume all messages on disk have message-ids
    try:
      header =  ''.join(message.getfirstmatchingheader('message-id'))
    except KeyError:
      # No message ID was found. Warn the user and move on
      print
      print "WARNING: Message #%d in %s" % (i, filename),
      print "has no Message-Id header."
 
    header = BLANKS_RE.sub(' ', header.strip())
    try:
      msg_id = MSGID_RE.match(header).group(1)
      if msg_id not in messages.keys():
        # avoid adding dupes
        messages[msg_id] = msg_id
    except AttributeError:
      # Message-Id was found but could somehow not be parsed by regexp
      # (highly bloody unlikely)
      print
      print "WARNING: Message #%d in %s" % (i, foldername),
      print "has a malformed Message-Id header."
    spinner.spin()
    i = i + 1
 
  # done
  mbox.close()
  spinner.stop()
  print ": %d messages" % (len(messages.keys()))
  return messages
 
def scan_folder(server, foldername):
  """Gets IDs of messages in the specified folder, returns id:num dict"""
  messages = {}
  spinner = Spinner("Folder %s" % (foldername))
  try:
    typ, data = server.select(foldername, readonly=True)
    if 'OK' != typ:
      raise SkipFolderException("SELECT failed: %s" % (data))
    num_msgs = int(data[0])
 
    # each message
    for num in range(1, num_msgs+1):
      # Retrieve Message-Id
      typ, data = server.fetch(num, '(BODY[HEADER.FIELDS (MESSAGE-ID)])')
      if 'OK' != typ:
        raise SkipFolderException("FETCH %s failed: %s" % (num, data))
 
      header = data[0][1].strip()
      # remove newlines inside Message-Id (a dumb Exchange trait)
      header = BLANKS_RE.sub(' ', header)
      try:
        msg_id = MSGID_RE.match(header).group(1) 
        if msg_id not in messages.keys():
          # avoid adding dupes
          messages[msg_id] = num
      except (IndexError, AttributeError):
        # Some messages may have no Message-Id, so we'll synthesise one
        # (this usually happens with Sent, Drafts and .Mac news)
        typ, data = server.fetch(num, '(BODY[HEADER.FIELDS (FROM TO CC DATE SUBJECT)])')
        if 'OK' != typ:
          raise SkipFolderException("FETCH %s failed: %s" % (num, data))
        header = data[0][1].strip()
        header = header.replace('\r\n','\t')
        messages['<' + UUID + '.' + sha.sha(header).hexdigest() + '>'] = num
      spinner.spin()
  finally:
    spinner.stop()
    print ":",
 
  # done
  print "%d messages" % (len(messages.keys()))
  return messages
 
def parse_paren_list(row):
  """Parses the nested list of attributes at the start of a LIST response"""
  # eat starting paren
  assert(row[0] == '(')
  row = row[1:]
 
  result = []
 
  # NOTE: RFC3501 doesn't fully define the format of name attributes 
  name_attrib_re = re.compile("^\s*(\\\\[a-zA-Z0-9_]+)\s*")
 
  # eat name attributes until ending paren
  while row[0] != ')':
    # recurse
    if row[0] == '(':
      paren_list, row = parse_paren_list(row)
      result.append(paren_list)
    # consume name attribute
    else:
      match = name_attrib_re.search(row)
      assert(match != None)
      name_attrib = row[match.start():match.end()]
      row = row[match.end():]
      #print "MATCHED '%s' '%s'" % (name_attrib, row)
      name_attrib = name_attrib.strip()
      result.append(name_attrib)
 
  # eat ending paren
  assert(')' == row[0])
  row = row[1:]
 
  # done!
  return result, row
 
def parse_string_list(row):
  """Parses the quoted and unquoted strings at the end of a LIST response"""
  slist = re.compile('\s*(?:"([^"]+)")\s*|\s*(\S+)\s*').split(row)
  return [s for s in slist if s]
 
def parse_list(row):
  """Prases response of LIST command into a list"""
  row = row.strip()
  paren_list, row = parse_paren_list(row)
  string_list = parse_string_list(row)
  assert(len(string_list) == 2)
  return [paren_list] + string_list
 
def get_hierarchy_delimiter(server):
  """Queries the imapd for the hierarchy delimiter, eg. '.' in INBOX.Sent"""
  # see RFC 3501 page 39 paragraph 4
  typ, data = server.list('', '')
  assert(typ == 'OK')
  assert(len(data) == 1)
  lst = parse_list(data[0]) # [attribs, hierarchy delimiter, root name]
  hierarchy_delim = lst[1]
  # NIL if there is no hierarchy
  if 'NIL' == hierarchy_delim:
    hierarchy_delim = '.'
  return hierarchy_delim
 
def get_names(server, compress):
  """Get list of folders, returns [(FolderName,FileName)]"""
 
  spinner = Spinner("Finding Folders")
 
  # Get hierarchy delimiter
  delim = get_hierarchy_delimiter(server)
  spinner.spin()
 
  # Get LIST of all folders
  typ, data = server.list()
  assert(typ == 'OK')
  spinner.spin()
 
  names = []
 
  # parse each LIST, find folder name
  for row in data:
    lst = parse_list(row)
    foldername = lst[2]
    suffix = {'none':'', 'gzip':'.gz', 'bzip2':'.bz2'}[compress]
    filename = '.'.join(foldername.split(delim)) + '.mbox' + suffix
    names.append((foldername, filename))
 
  # done
  spinner.stop()
  print ": %s folders" % (len(names))
  return names
 
def print_usage():
  """Prints usage, exits"""
  #     "                                                                               "
  print "Usage: imapbackup [OPTIONS] -s HOST -u USERNAME [-p PASSWORD]"
  print " -a --append-to-mboxes     Append new messages to mbox files. (default)"
  print " -y --yes-overwrite-mboxes Overwite existing mbox files instead of appending."
  print " -n --compress=none        Use one plain mbox file for each folder. (default)"
  print " -z --compress=gzip        Use mbox.gz files.  Appending may be very slow."
  print " -b --compress=bzip2       Use mbox.bz2 files. Appending not supported: use -y."
  print " -f --=folder              Specifify which folders use.  Comma separated list."
  print " -e --ssl                  Use SSL.  Port defaults to 993."
  print " -k KEY --key=KEY          PEM private key file for SSL.  Specify cert, too."
  print " -c CERT --cert=CERT       PEM certificate chain for SSL.  Specify key, too."
  print "                           Python's SSL module doesn't check the cert chain."
  print " -s HOST --server=HOST     Address of server, port optional, eg. mail.com:143"
  print " -u USER --user=USER       Username to log into server"
  print " -p PASS --pass=PASS       Prompts for password if not specified."
  print " -K KEY --sqkey=KEY        Squirtle KEY to use."
  print " -L x --loop=x             Loop and loop and loop, waiting 'x' seconds btwn loops"
  print "\nNOTE: Maildir is created in a directory based upon username"
  sys.exit(2)
 
def process_cline():
  """Uses getopt to process command line, returns (config, warnings, errors)"""
  # read command line
  try:
    short_args = "aynzbek:c:s:u:p:f:K:L:"
    long_args = ["append-to-mboxes", "yes-overwrite-mboxes", "compress=", "sqkey=", "loop="
                 "ssl", "keyfile=", "certfile=", "server=", "user=", "pass=", "folders="]
    opts, extraargs = getopt.getopt(sys.argv[1:], short_args, long_args)
  except getopt.GetoptError:
    print_usage()
 
  warnings = []
  config = {'compress':'none', 'overwrite':False, 'usessl':False}
  errors = []
 
  # empty command line
  if not len(opts) and not len(extraargs):
    print_usage()
 
  # process each command line option, save in config
  for option, value in opts:
    if option in ("-a", "--append-to-mboxes"):
      config['overwrite'] = False
    elif option in ("-y", "--yes-overwrite-mboxes"):
      warnings.append("Existing mbox files will be overwritten!")
      config["overwrite"] = True
    elif option == "-n":
      config['compress'] = 'none'
    elif option == "-z":
      config['compress'] = 'gzip'
    elif option == "-b":
      config['compress'] = 'bzip2'
    elif option == "--compress":
      if value in ('none', 'gzip', 'bzip2'):
        config['compress'] = value
      else:
        errors.append("Invalid compression type specified.")
    elif option in ("-e", "--ssl"):
      config['usessl'] = True
    elif option in ("-k", "--keyfile"):
      config['keyfilename'] = value
    elif option in ("-f", "--folders"):
      config['folders'] = value
    elif option in ("-c", "--certfile"):
      config['certfilename'] = value
    elif option in ("-s", "--server"):
      config['server'] = value
    elif option in ("-u", "--user"):
      config['user'] = value
    elif option in ("-p", "--pass"):
      config['pass'] = value
    elif option in ("-K", "--sqkey"):
      config['sqkey'] = value
    elif option in ("-L", "--loop"):
      config['loop'] = value
    else:
      errors.append("Unknown option: " + option)
 
  # don't ignore extra arguments
  for arg in extraargs:
    errors.append("Unknown argument: " + arg)
 
  # done processing command line
  return (config, warnings, errors)
 
def check_config(config, warnings, errors):
  """Checks the config for consistency, returns (config, warnings, errors)"""
 
  if config['compress'] == 'bzip2' and config['overwrite'] == False:
    errors.append("Cannot append new messages to mbox.bz2 files.  Please specify -y.")
  if config['compress'] == 'gzip' and config['overwrite'] == False:
    warnings.append(
      "Appending new messages to mbox.gz files is very slow.  Please Consider\n"
      "  using -y and compressing the files yourself with gzip -9 *.mbox")
  if 'server' not in config :
    errors.append("No server specified.")
  if 'user' not in config:
    errors.append("No username specified.")
  if ('keyfilename' in config) ^ ('certfilename' in config):
    errors.append("Please specify both key and cert or neither.")
  if 'keyfilename' in config and not config['usessl']:
    errors.append("Key specified without SSL.  Please use -e or --ssl.")
  if 'certfilename' in config and not config['usessl']:
    errors.append("Certificate specified without SSL.  Please use -e or --ssl.")
  if 'server' in config and ':' in config['server']:
    # get host and port strings
    bits = config['server'].split(':', 1)
    config['server'] = bits[0]
    # port specified, convert it to int
    if len(bits) > 1 and len(bits[1]) > 0:
      try:
        port = int(bits[1])
        if port > 65535 or port < 0:
          raise ValueError
        config['port'] = port
      except ValueError:
        errors.append("Invalid port.  Port must be an integer between 0 and 65535.")
  return (config, warnings, errors)
 
def get_config():
  """Gets config from command line and console, returns config"""
  # config = {
  #   'compress': 'none' or 'gzip' or 'bzip2'
  #   'overwrite': True or False
  #   'server': String
  #   'port': Integer
  #   'user': String
  #   'pass': String
  #   'usessl': True or False
  #   'keyfilename': String or None
  #   'certfilename': String or None
  # }
 
  config, warnings, errors = process_cline()
  config, warnings, errors = check_config(config, warnings, errors)
 
  # show warnings
  for warning in warnings:
    print "WARNING:", warning
 
  # show errors, exit
  for error in errors:
    print "ERROR", error
  if len(errors):
    sys.exit(2)
 
  # prompt for password, if necessary
  if 'pass' not in config and 'sqkey' not in config:
    config['pass'] = getpass.getpass()
 
  # defaults
  if not 'port' in config:
    if config['usessl']:
      config['port'] = 993
    else:
      config['port'] = 143
 
  # done!
  return config
 
def connect_and_login(config):
  """Connects to the server and logs in.  Returns IMAP4 object."""
  try:
    assert(not (('keyfilename' in config) ^ ('certfilename' in config)))
 
    if config['usessl'] and 'keyfilename' in config:
      print "Connecting to '%s' TCP port %d," % (config['server'], config['port']),
      print "SSL, key from %s," % (config['keyfilename']),
      print "cert from %s " % (config['certfilename'])
      server = imaplib.IMAP4_SSL(config['server'], config['port'],
                                 config['keyfilename'], config['certfilename'])
    elif config['usessl']:
      print "Connecting to '%s' TCP port %d, SSL" % (config['server'], config['port'])
      server = imaplib.IMAP4_SSL(config['server'], config['port'])
    else:
      print "Connecting to '%s' TCP port %d" % (config['server'], config['port'])
      server = imaplib.IMAP4(config['server'], config['port'])

    if 'sqkey' in config:
      print "Logging in with Squirtle key '%s'" % (config['sqkey'])
      login_squirtle(server, config['sqkey'])
    else:
      print "Logging in as '%s'" % (config['user'])
      server.login(config['user'], config['pass'])
  except socket.gaierror, e:
    (err, desc) = e
    print "ERROR: problem looking up server '%s' (%s %s)" % (config['server'], err, desc)
    sys.exit(3)
  except socket.error, e:
    if str(e) == "SSL_CTX_use_PrivateKey_file error":
      print "ERROR: error reading private key file '%s'" % (config['keyfilename'])
    elif str(e) == "SSL_CTX_use_certificate_chain_file error":
      print "ERROR: error reading certificate chain file '%s'" % (config['keyfilename'])
    else:
      print "ERROR: could not connect to '%s' (%s)" % (config['server'], e)
 
    sys.exit(4)
 
  return server
 
def process_messages(server, config):
    names = get_names(server, config['compress'])
 
    if config.get('folders'):
      dirs = map (lambda x: x.strip(), config.get('folders').split(','))
      names = filter (lambda x: x[0] in dirs, names)
 
    #for n in range(len(names)):
    #  print n, names[n]
    
    for name_pair in names:
      try:
        foldername, filename = name_pair
        fol_messages = scan_folder(server, foldername)
        fil_messages = scan_file(config['user'], foldername, config['compress'], config['overwrite'])
 
        new_messages = {}
        for msg_id in fol_messages:
          if msg_id not in fil_messages:
            new_messages[msg_id] = fol_messages[msg_id]
 
        #for f in new_messages:
        #  print "%s : %s" % (f, new_messages[f])
 
        download_messages(server, config['user'], foldername, new_messages, config)
 
      except SkipFolderException, e:
        print e

def main():
  """Main entry point"""
  try:
    config = get_config()
    server = connect_and_login(config)

    """Check to see if Maildir exists, create if not"""
    path = config['user']
    if not os.path.isdir(path):
      os.mkdir(path, 0700)
      os.mkdir(os.path.join(path, 'tmp'), 0700)
      os.mkdir(os.path.join(path, 'new'), 0700)
      os.mkdir(os.path.join(path, 'cur'), 0700)

    if 'loop' in config:
      while 1:
        process_messages(server, config)
        print "---------------------------------------------------------"
        time.sleep(float(config['loop']))
    else:
      process_messages(server, config)
    
    print "Disconnecting"
    server.logout()
  except socket.error, e:
    (err, desc) = e
    print "ERROR: %s %s" % (err, desc)
    sys.exit(4)
  except imaplib.IMAP4.error, e:
    print "ERROR:", e
    sys.exit(5)
 
 
# From http://www.pixelbeat.org/talks/python/spinner.py
def cli_exception(typ, value, traceback):
  """Handle CTRL-C by printing newline instead of ugly stack trace"""
  if not issubclass(typ, KeyboardInterrupt):
    sys.__excepthook__(typ, value, traceback)
  else:
    sys.stdout.write("\n")
    sys.stdout.flush()
 
if sys.stdin.isatty():
  sys.excepthook = cli_exception
 
 
 
# Hideous fix to counteract http://python.org/sf/1092502
# (which should have been fixed ages ago.)
# Also see http://python.org/sf/1441530
def _fixed_socket_read(self, size=-1):
  data = self._rbuf
  if size < 0:
    # Read until EOF
    buffers = []
    if data:
      buffers.append(data)
    self._rbuf = ""
    if self._rbufsize <= 1:
      recv_size = self.default_bufsize
    else:
      recv_size = self._rbufsize
    while True:
      data = self._sock.recv(recv_size)
      if not data:
        break
      buffers.append(data)
    return "".join(buffers)
  else:
    # Read until size bytes or EOF seen, whichever comes first
    buf_len = len(data)
    if buf_len >= size:
      self._rbuf = data[size:]
      return data[:size]
    buffers = []
    if data:
      buffers.append(data)
    self._rbuf = ""
    while True:
      left = size - buf_len
      recv_size = min(self._rbufsize, left) # the actual fix
      data = self._sock.recv(recv_size)
      if not data:
        break
      buffers.append(data)
      n = len(data)
      if n >= left:
        self._rbuf = data[left:]
        buffers[-1] = data[:left]
        break
      buf_len += n
    return "".join(buffers)
 
# Platform detection to enable socket patch
if 'Darwin' in platform.platform() and '2.3.5' == platform.python_version():
  socket._fileobject.read = _fixed_socket_read
if 'Windows' in platform.platform():
  socket._fileobject.read = _fixed_socket_read
 
if __name__ == '__main__':
  gc.enable()
  main()
