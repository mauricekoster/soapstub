#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import os
from os.path import basename
import xml.etree.ElementTree as ET
import re, sys
import socket
PORT_NUMBER = 8000

wsdlmap = {  }
rules = {}

def read_rules(ruleset):
    #try:
    l = []
    current = []

    f = open( ruleset + ".rules", 'r')
    print "Reading ruleset %s" % ruleset

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

      elif m[0] == '+':
        regexp = m[2]
        regexp = regexp.strip('^')
        regexp = regexp.strip('$')
        regexp = '^'+ regexp + '$'
        if len(m) == 3:
            current.append( (m[1], regexp) )

        elif len(m) == 4:
          current.append( (m[1], regexp) )
          t = (current, m[3])
          # got reply, rule done
          l.append(t)
          current = []

        else:
          print "error in rule: ", line
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
        regexp = m[1]
        regexp = regexp.strip('^')
        regexp = regexp.strip('$')
        regexp = '^'+ regexp + '$'
        if len(m) == 2:
          current.append( (m[0], regexp) )

        elif len(m) == 3:
          current.append( (m[0], regexp) )
          t = (current, m[2])
          # got reply, rule done
          l.append(t)
          current = []

    rules[ruleset] = l

    f.close()
    #except:
    #pass

    for r in rules[ruleset]:
      print r

def read_wsdlmap():
  print "Reading wsdl map"
  try:
    f = open('wsdl.conf','r')
    for line in f.readlines():
      line = line.strip('\r\n')

      if not line.strip():
        continue

      if line.startswith('#'):
        continue

      m = re.split('\s\s+', line)

      wsdlmap[ m[0] ] = m[1].strip('\n')

    f.close()
  except:
    pass

  #print "Done"
  #print wsdlmap

#This class will handles any incoming request from the browser
class myHandler(BaseHTTPRequestHandler):



  def do_POST(self):
    sendReply = False
    l = self.headers['Content-Length']
    l = int(l)
    content = self.rfile.read(l)
    #print content

    # line = content.split('\n')[0]
    # line = line.strip('\r\n')
    # line = line[1:-1]
    # print "> ", line
    # m = line.split()
    # ns = {}
    # for l in m:
    #   if l.startswith('xmlns'):
    #     l = l[6:]
    #     n, url = l.split('=')
    #     ns[n] = url.strip('"')
    #
    # print ns
    root = ET.fromstring(content)




    req = root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Body/[0]')
    req = list(req)[0]
    ruleset = req.tag.split('}')[1]

    if not ruleset in rules:
      read_rules(ruleset)

    values = {}
    print "Start matching..."
    rule_id = 0
    for rule in rules[ ruleset ]:
      rule_id += 1

      if len(rule) == 1:
        print "MATCHED DEFAULT RULE"
        reply = rule[0]
        sendReply = True
        break

      else:
        #print "Rule: ", rule
        reply = rule[1]
        all_matched = True
        l = rule[0]
        values = {}
        idx = 0
        for r in l:
          xpath = r[0]
          regexp = r[1]
          idx += 1
          elem = root.find(xpath) # , namespaces=ns
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
          print "MATCHED RULE '%d'. Values " % rule_id, values
          sendReply = True
          break



    if sendReply == True:
      #Open the static file requested and send it
      f = open( os.path.join(os.curdir, reply) )
      self.send_response(200)
      self.send_header('Content-type','text/xml')
      self.end_headers()
      content = f.read()
      content = content.replace('\r\n','\n')
      content = content.replace('\n','\r\n')
      content = content.replace('{{VALUE}}', value)
      for k, v in values.items():
        content = content.replace('{{%s}}' % k, v)

      self.wfile.write(content)
      f.close()
      return

  #Handler for the GET requests
  def do_GET(self):
    #print basename(self.path)

    try:
      #Check the file extension required and
 	   #set the right mime type

      sendReply = False


      mimetype='text/xml'

      if self.path in wsdlmap:
        self.path = wsdlmap[self.path]
        sendReply = True

      else:
        if self.path.endswith(".wsdl") or self.path.endswith("?wsdl"):
          sendReply = True

        if self.path.endswith(".xsd"):
          sendReply = True

      if sendReply == True:
 	     #Open the static file requested and send it
        f = open( os.path.join(os.curdir, self.path))
        self.send_response(200)
        self.send_header('Content-type',mimetype)
        self.end_headers()
        content = f.read()
        content = content.replace('\r\n','\n')
        server = '%s:%d' % (socket.getfqdn(), PORT_NUMBER)
        content = content.replace('{{SERVER}}', server)
        self.wfile.write(content)
        f.close()
        return

      else:
        self.send_error(404,'File Not Found: %s' % self.path)

    except IOError:
      self.send_error(404,'File Not Found: %s' % self.path)

try:
  read_wsdlmap()

  # Create a web server and define the handler to manage the
  #incoming request
  server = HTTPServer(('', PORT_NUMBER), myHandler)
  print 'Started httpserver on port %s:%d' % (socket.getfqdn(), PORT_NUMBER)

  #Wait forever for incoming htto requests
  server.serve_forever()

except KeyboardInterrupt:
  print '^C received, shutting down the web server'

  server.socket.close()
