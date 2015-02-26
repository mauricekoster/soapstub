#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import os, glob
from os.path import basename
import xml.etree.ElementTree as ET
import re, sys
import socket
import logging

import argparse

# === Configuration ========================================================================
argparser = argparse.ArgumentParser()
argparser.add_argument("--dir", help="Base directory.")
args = argparser.parse_args()

if args.dir:
    base_dir = os.path.normpath(args.dir)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

PORT_NUMBER = 8989

wsdlmap = {}
wsdlmap_modified = None

rules = {}
variables = {}
rules_modified = {}

# store last request of ruleset, enabling to retrieve it to check its content
last_requests = {}

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

logger.info("basedir: %s" % base_dir)

def sanitize_rule(rule, namespace):
  data = rule.replace('//', '/~/')
  pattern = re.compile(r"((?:{[^}]*}|[^/]*)*)")
  l = pattern.split(data)[1::2]

  ll = []
  for i in l:
    if i == '~':
      i = ''
    elif not i in ['','.']:
      if i[0] != '{':
        logger.debug("i: %s" % i)
        i = "{%s}%s" % (namespace['default'], i)
      else:
        p = i.find('}')
        if p > -1:
          ns = i[1:p]
          ns = ns.replace('/~/','//')
          logger.debug("namespace: %s" % ns)
          if ns in namespace:
            i = "{%s}%s" % (namespace[ns], i[p+1:])
          else:
            i = i.replace('/~/','//')

    ll.append(i)

  new_rule = '/'.join(ll)
  return new_rule

def check_rule_file_modified(ruleset):
  fn = os.path.join(base_dir, ruleset + ".rules")
  mt = os.path.getmtime(fn)
  if ruleset in rules_modified:
    if mt > rules_modified[ruleset]:
      return True
  else:
    return True

  return False

def check_wsdlmap_modified():
  fn = os.path.join(base_dir, "wsdl.conf")
  logger.info("check wsdl.conf: %s" % fn)
  mt = os.path.getmtime(fn)

  if wsdlmap_modified is None:
    logger.debug("wsdl map not loaded")
    return True

  if mt > wsdlmap_modified:
    logger.debug("wsdl map changed")
    return True

  return False

def read_rules(ruleset):
    #try:
    l = []
    current = []
    current_namespace = {}
    current_variables = {}

    fn = os.path.join(base_dir, ruleset + ".rules")

    f = open( fn, 'r')
    logger.info( "Reading ruleset '%s'" % ruleset )
    mt = os.path.getmtime(fn)
    rules_modified[ruleset] = mt

    for line in f.readlines():
      line = line.strip('\r\n')

      if not line.strip():
        continue

      line = line.strip()
      if line.startswith('#'):
        continue

      m = re.split('\s\s+', line)
      if m[0] == 'default' or m[0] == '*':
        t = (m[-1], )
        l.append( t )
        current = []

      elif m[0] == 'namespace':
        if len(m) == 2:
          current_namespace['default'] = m[1]
        else:
          current_namespace[m[1]] = m[2]

      elif m[0] == 'variable':
        rule = sanitize_rule( m[2], current_namespace )
        current_variables[m[1]] = rule

      elif m[0] == '+':
        rule = sanitize_rule(m[1], current_namespace)

        regexp = m[2]
        regexp = regexp.strip('^')
        regexp = regexp.strip('$')
        regexp = '^'+ regexp + '$'
        if len(m) == 3:
            current.append( (rule, regexp) )

        elif len(m) == 4:
          current.append( (rule, regexp) )
          t = (current, m[3])
          # got reply, rule done
          l.append(t)
          current = []

        else:
          logger.critical( "error in rule: %d" % line )
          sys.exit(1)

      elif m[0] == '=>':
        t = (current, m[1])
        # got reply, rule done
        l.append(t)
        current = []

      elif m[0].startswith('=>'):
        m = m[0].split()
        t = (current, m[1])
        # got reply, rule done
        l.append(t)
        current = []

      else:
        rule = sanitize_rule( m[0], current_namespace )

        regexp = m[1]
        regexp = regexp.strip('^')
        regexp = regexp.strip('$')
        regexp = '^'+ regexp + '$'
        if len(m) == 2:
          current.append( (rule, regexp) )

        elif len(m) == 3:
          current.append( (rule, regexp) )
          t = (current, m[2])
          # got reply, rule done
          l.append(t)
          current = []

    rules[ruleset] = l
    variables[ruleset] = current_variables
    f.close()

    #dump_rules(ruleset)

def dump_rules(ruleset):
    print "-" * 60
    print "Rules:"
    idx = 0
    for r in rules[ruleset]:
      idx += 1
      print "Rule %d:" % idx

      if len(r) == 1:
        print "\tdefault => %s" % r[0]
      else:
        partno = 0
        for i in r[0]:
          partno += 1
          print "    Part no %d" % partno
          print "\txpath : %s" % i[0]
          print "\tregex : %s" % i[1]
        print "    Reply : %s" % r[1]
      print ""
    print "-" * 60

def read_wsdlmap():
  logger.info("Reading wsdl map from %s" % base_dir)
  global wsdlmap
  global wsdlmap_modified
  wsdlmap = {}

  try:
    fn = os.path.join(base_dir, 'wsdl.conf')
    mt = os.path.getmtime(fn)
    wsdlmap_modified = mt
    #logger.debug(mt)

    f = open(fn,'r')
    for line in f.readlines():
      line = line.strip('\r\n')

      if not line.strip():
        continue

      if line.startswith('#'):
        continue

      m = re.split('\s\s+', line)

      wsdlmap[ m[0] ] = m[1].strip('\n')

    #logger.debug('+++')
    f.close()


  except:
    pass

  #logger.debug('..done..')
  #print "Done"
  #print wsdlmap

def preload_rulesets():
  for f in glob.glob('*.rules'):
    fn = f[:-6]
    read_rules(fn)

#This class will handles any incoming request from the browser
class myHandler(BaseHTTPRequestHandler):

  def send_last_request(self, ruleset):
    if ruleset in last_requests:
      content = last_requests[ruleset]
    else:
      content = ""

    s = len(content)
    self.send_response(200)
    self.send_header('Content-type','text/xml')
    self.send_header('Content-Length', s)
    self.end_headers()

    self.wfile.write(content)

  def send_reply(self, reply, values):
    r = reply.replace('/', os.sep)
    fn = os.path.join(base_dir, r)
    logger.info("Returning reply %s" % fn)
    f = open( fn, 'r' )
    self.send_response(200)
    self.send_header('Content-type','text/xml')
    self.end_headers()
    content = f.read()
    content = content.replace('\r\n','\n')
    content = content.replace('\n','\r\n')

    for k, v in values.items():
      content = content.replace('{{%s}}' % k, v)

    self.wfile.write(content)
    f.close()


  def send_wsdl_reply(self):
    #logger.debug('Enter send_wsdl_reply')
    r = self.path.replace('/', os.sep)
    #logger.debug("Basedir: %s Reply %s -> %s" % (base_dir,self.path,r))
    fn = os.path.join(base_dir, r)
    logger.info("Returning WSDL %s" % fn)
    f = open( fn, 'r' )
    #logger.debug('file opened')

    #s = os.path.getsize(fn)
    #logger.debug("wsdl file-size: %d" % s)

    content = f.read()
    #print content

    content = content.replace('\r\n','\n')
    server = '%s:%d' % (socket.getfqdn(), PORT_NUMBER)
    content = content.replace('{{SERVER}}', server)


    s = len(content)
    print "wsdl file-size: %d" % s

    self.send_response(200)
    self.send_header('Content-type', 'text/xml')
    self.send_header('Content-Length', s)
    self.end_headers()


    self.wfile.write(content)
    f.close()


  def send_html_content(self, content):
    s = len(content)

    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header('Content-Length', s)
    self.end_headers()

    self.wfile.write(content)

  def send_listing(self):
    content = """
    <html>
    <body>"""

    content += "<h1>Content</h1>"

    content += "<h2>WSDL list</h2><ul>"
    wsdllist = ""
    for w in wsdlmap.keys():
      wsdllist += '<li><a href="%s">%s</a></li>' % (w, w)

    content += wsdllist
    content += "</ul>"

    rulelist = ""
    for r in rules.keys():
      rulelist += '<li><a href="%s">%s</a></li>' % ('/list/' + r, r)

    content += """
      <h2>Rulesets</h2>
      <ul>
      %s
      </ul>
      """  % rulelist

    content += "</body></html>"

    self.send_html_content(content)

  def send_list_rules(self, ruleset):
    rule_id = 0
    content = "<html><body>"
    content += "<h1>Ruleset <em>%s</em></h1>" % ruleset
    content += "<table border=1>"
    content += "<tr><th>RuleNr<th>#<th>XPath<th>RegExp</tr>"
    for rule in rules[ ruleset ]:
      rule_id += 1
      row_span = 1

      if len(rule) == 1:
        content += "<tr><th rowspan=2>%d<td colspan='3'>Default rule</td></tr>" % rule_id
        content += "<tr><th>R<td colspan=2><strong>%s</strong></tr>" % ( rule[0] )
      else:
        first = True
        row_span = len(rule[0]) + 1
        idx = 0
        for r in rule[0]:
          idx += 1
          xpath = r[0]
          regexp = r[1]
          content += "<tr>"
          if first:
            first = False
            content += "<th rowspan='%d'>%d" % (row_span, rule_id)
          content += "<td>%d<td>%s<td>%s</tr>" % ( idx, xpath, regexp)
        content += "<tr><th>R<td colspan=2><strong>%s</strong></tr>" % ( rule[1] )


    content += "</table>"
    content += "<a href='/source/%s'>Source</a> - " % ruleset
    content += "<a href='/'>Back</a>"
    content += "</body></html>"
    self.send_html_content(content)

  def send_source_rules(self, ruleset):
    fn = os.path.join(base_dir, ruleset + '.rules')
    f = open( fn, 'r' )
    filecontent = f.read()
    filecontent = filecontent.replace('\r\n','\n')
    filecontent = filecontent.replace('\n','<br/>')
    f.close()

    content = "<html><body><h1>Source <em>%s</em></h1>" % ruleset
    content += "<table border=1>"
    content += "<tr><td><pre>%s</pre></tr>" % filecontent
    content += "</table>"
    content += "<a href='/list/%s'>Back</a>" % ruleset
    content += "</body></html>"

    self.send_html_content(content)

  def do_POST(self):
    sendReply = False

    # Get request content
    l = self.headers['Content-Length']
    l = int(l)
    content = self.rfile.read(l)
    root = ET.fromstring(content)

    # Get SOAP body (SOAP 1.1)
    req = root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Body')

    if req is None:
      # Try SOAP 1.2:
      logger.info( "SOAP 1.2 request detected" )
      req = root.find('.//{http://www.w3.org/2003/05/soap-envelope}Body')

    req = list(req)[0]

    # determine the ruleset based on 1st tag found inside body
    ruleset = req.tag.split('}')[1]

    # Store last request
    last_requests[ruleset] = content

    # check if ruleset needs to be (re)loaded
    if check_rule_file_modified(ruleset):
      logger.debug("ruleset modified")
      rules.pop(ruleset, None)

    # Load ruleset if not loaded
    if not ruleset in rules:
      read_rules(ruleset)

    values = {}
    variable_values = {}
    logger.info("Start matching using ruleset %s" % ruleset)
    rule_id = 0

    for varname, xpath in variables[ ruleset ].items():
      # print "variables:"
      # print "%s => %s" % (varname, xpath)
      elem = root.find(xpath) # , namespaces=ns
      if elem is None:
        logger.warning("variable '%s' not found on xpath: %s" % (varname, xpath))
      else:
        variable_values[varname] = elem.text

    for rule in rules[ ruleset ]:
      rule_id += 1

      if len(rule) == 1:
        logger.info("Matched default rule")
        reply = rule[0]
        sendReply = True
        break

      else:
        #print "Rule: ", rule
        reply = rule[1]
        all_matched = True
        l = rule[0]
        values = variable_values.copy()
        idx = 0
        for r in l:
          xpath = r[0]
          regexp = r[1]
          idx += 1
          elem = root.find(xpath) # , namespaces=ns
          if elem is None:
            # xpath not found
            logger.error( "xpath error in rule %d part %s" % (rule_id ,xpath) )
            all_matched = False
            break

          value = elem.text
          if not value:
            value = ""

          match = re.match(regexp, value)
          if not match:
            # next rule
            all_matched = False
            break

          values[idx] = value

        if all_matched:
          logger.info( "Matched rule '%d'. Values: %s" % (rule_id, str(values)) )
          sendReply = True
          break



    if sendReply == True:
      #Open the static file requested and send it
      for k, v in values.items():
        reply = reply.replace('{{%s}}' % k, v)

      self.send_reply(reply, values)

    else:
      logger.info("No rules matched")

      self.send_error(404,'No rules matched')



  #Handler for the GET requests
  def do_GET(self):
    #print basename(self.path)

    try:

      if check_wsdlmap_modified():
        read_wsdlmap()

      #logger.debug('request: %s' % self.path)
      if self.path in wsdlmap:
        self.path = wsdlmap[self.path]
        #logger.debug('in map')
        self.send_wsdl_reply()

      else:
        #logger.debug('from file')
        if self.path.endswith(".wsdl") or self.path.endswith("?wsdl"):
          self.send_wsdl_reply()

        elif self.path.endswith(".xsd"):
          self.send_wsdl_reply()

        elif self.path == "/":
          # overview
          self.send_listing()

        elif self.path.startswith('/list/'):
          ruleset = self.path[6:]
          self.send_list_rules(ruleset)

        elif self.path.startswith('/last/'):
          ruleset = self.path[6:]
          self.send_last_request(ruleset)

        elif self.path.startswith('/source/'):
          ruleset = self.path[8:]
          self.send_source_rules(ruleset)

        else:
          self.send_error(404,'URL not resolved: %s' % self.path)

    except IOError:
      self.send_error(500,'Internal error for URL: %s' % self.path)

    except:
      logger.error('huh?')

try:
  read_wsdlmap()
  preload_rulesets()

  # Create a web server and define the handler to manage the
  #incoming request
  fqdn = '' # socket.getfqdn()
  server = HTTPServer((fqdn, PORT_NUMBER), myHandler)
  logger.info( 'Started httpserver on %s port %d' % (fqdn or 'localhost', PORT_NUMBER) )

  #Wait forever for incoming htto requests
  server.serve_forever()

except KeyboardInterrupt:
  print '^C received, shutting down the web server'

  server.socket.close()
