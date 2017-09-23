from __future__ import print_function

import base64
import email.parser
import io
import multiprocessing
import netaddr
import os
import psutil
import pywintypes
import re
import select
import signal
import socket
import sspi
import sys
import threading
import time
import traceback
import urllib
import win32api
import win32timezone

try:
	import configparser
	import http.server as httpserver
	import socketserver
	import urllib.parse as urlparse
except:
	import ConfigParser as configparser
	import SimpleHTTPServer as httpserver
	import SocketServer as socketserver
	import urlparse

import concurrent.futures

DEBUG = False
EXIT = False
LISTEN = '127.0.0.1'
LOGGER = None
NOPROXY = netaddr.IPSet([])
NTLM_PROXY = None
PORT = 3128

MAX_IDLE = 30
MAX_DISCONNECT = 3
MAX_LINE = 65536 + 1
MAX_THREADS = 40
MAX_WORKERS = 2

INI = "px.ini"

class Log(object):
	def __init__(self, name, mode):
		self.file = open(name, mode)
		self.stdout = sys.stdout
		self.stderr = sys.stderr
		sys.stdout = self
		sys.stderr = self
	def close(self):
		sys.stdout = self.stdout
		sys.stderr = self.stderr
		self.file.close()
	def write(self, data):
		self.file.write(data)
		self.file.flush()
		self.stdout.write(data)
	def flush(self):
		self.file.flush()

def dprint(*objs):
	if DEBUG:
		print(multiprocessing.current_process().name + ": " + threading.current_thread().name + ": " + str(int(time.time())) + ": " + sys._getframe(1).f_code.co_name + ": ", end="")
		print(*objs)

class NtlmMessageGenerator:
	def __init__(self,user=None):
		if not user:
			user = win32api.GetUserName()
		self.sspi_client = sspi.ClientAuth("NTLM", user, scflags=0)

	def create_auth_request(self):
		output_buffer = None
		error_msg = None
		try:
			error_msg, output_buffer = self.sspi_client.authorize(None)
		except pywintypes.error:
			return None

		auth_req = output_buffer[0].Buffer
		auth_req = base64.encodestring(auth_req)
		auth_req = auth_req.decode("utf-8").replace('\012', '')
		return auth_req

	def create_challenge_response(self, challenge):
		output_buffer = None
		input_buffer = challenge
		error_msg = None
		try:
			error_msg, output_buffer = self.sspi_client.authorize(input_buffer)
		except pywintypes.error:
			traceback.print_exc(file=sys.stdout)
			return None
		response_msg = output_buffer[0].Buffer
		response_msg = base64.encodestring(response_msg)
		response_msg = response_msg.decode("utf-8").replace('\012', '')
		return response_msg

class Proxy(httpserver.SimpleHTTPRequestHandler):
	def handle_one_request(self):
		try:
			httpserver.SimpleHTTPRequestHandler.handle_one_request(self)
		except socket.error:
			if not hasattr(self, "_host_disconnected"):
				self._host_disconnected = 1
				dprint("Host disconnected")
			elif self._host_disconnected < MAX_DISCONNECT:
				self._host_disconnected += 1
				dprint("Host disconnected: %d" % self._host_disconnected)
			else:
				dprint("Closed connection to avoid infinite loop")
				self.close_connection = True

	def address_string(self):
		host, port = self.client_address[:2]
		#return socket.getfqdn(host)
		return host

	def do_socket(self, xheaders=[], destination=None):
		dprint("Entering")
		if not destination:
			destination = NTLM_PROXY

		if not hasattr(self, "client_socket") or self.client_socket == None:
			dprint("New connection")
			self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:				
				self.client_socket.connect(destination)
			except:
				traceback.print_exc(file=sys.stdout)
				return 503, None, None

		# No chit chat on SSL
		if destination != NTLM_PROXY and self.command == "CONNECT":
			return  200, None, None

		cl = None
		chk = False
		cmdstr = ("%s %s %s\r\n" % (self.command, self.path, self.request_version)).encode("utf-8")
		self.client_socket.send(cmdstr)
		dprint(cmdstr)
		for header in self.headers:
			h = ("%s: %s\r\n" % (header, self.headers[header])).encode("utf-8")
			self.client_socket.send(h)
			dprint("Sending %s" % h)

			if header.lower() == "content-length":
				cl = int(self.headers[header])
			elif header.lower() == "transfer-encoding" and self.headers[header].lower() == "chunked":
				dprint("CHUNKED data")
				chk = True

		for header in xheaders:
			h = ("%s: %s\r\n" % (header, xheaders[header])).encode("utf-8")
			self.client_socket.send(h)
			dprint("Sending extra %s" % h)
		self.client_socket.send(b"\r\n")

		if self.command in ["POST", "PUT", "PATCH"]:
			if not hasattr(self, "body"):
				dprint("Getting body for POST/PUT/PATCH")
				if cl != None:
					self.body = self.rfile.read(cl)
				else:	
					self.body = self.rfile.read()

			dprint("Sending body for POST/PUT/PATCH")
			self.client_socket.send(self.body)

		time.sleep(1)

		self.client_fp = self.client_socket.makefile("rb")

		resp = 503
		nobody = False
		headers = []
		body = b""
		
		if self.command == "HEAD":
			nobody = True

		# Response code
		dprint("Reading response code")
		line = self.client_fp.readline(MAX_LINE)
		try:
			resp = int(line.split()[1])
		except:
			if line == b"":
				dprint("Client closed connection")
				return 444, None, None
			dprint("Bad response %s" % line)
		if b"connection established" in line.lower() or resp == 204:
			nobody = True
		dprint("Response code: %d " % resp + str(nobody))

		# Headers
		cl = None
		chk = False
		dprint("Reading response headers")
		while not EXIT:
			line = self.client_fp.readline(MAX_LINE).decode("utf-8")
			if line == b"":
				dprint("Client closed connection: %s" % resp)
				return 444, None, None
			if line == "\r\n":
				break
			nv = line.split(":", 1)
			if len(nv) != 2:
				dprint("Bad header =>%s<=" % line)
				continue
			name = nv[0].strip()
			value = nv[1].strip()
			headers.append((name, value))
			dprint("Received header %s = %s" % (name, value))

			if name.lower() == "content-length":
				cl = int(value)
				if not cl:
					nobody = True
			elif name.lower() == "transfer-encoding" and value.lower() == "chunked":
				chk = True

		# Data
		dprint("Reading response data")
		if not nobody:
			if cl:
				dprint("Content length %d" % cl)
				body = self.client_fp.read(cl)
			elif chk:
				dprint("Chunked encoding")
				while not EXIT:
					line = self.client_fp.readline(MAX_LINE).decode("utf-8").strip()
					try:
						csize = int(line.strip(), 16)
						dprint("Chunk size %d" % csize)
					except:
						dprint("Bad chunk size '%s'" % line)
						continue
					if csize == 0:
						dprint("No more chunks")
						break
					d = self.client_fp.read(csize)
					if len(d) < csize:
						dprint("Chunk doesn't match data")
						break
					body += d
				headers.append(("Content-Length", str(len(body))))
			else:
				dprint("Not sure how much")
				while not EXIT:
					time.sleep(0.1)
					d = self.client_fp.read(1024)
					if len(d) < 1024:
						break
					body += d

		return resp, headers, body

	def do_transaction(self):
		dprint("Entering")

		ipport = self.get_destination()
		if ipport != None:
			dprint("Skipping NTLM proxying")
			resp, headers, body = self.do_socket(destination=ipport)
		else:
			# Check for NTLM auth
			ntlm = NtlmMessageGenerator()
			resp, headers, body = self.do_socket({
				"Proxy-Authorization": "NTLM %s" % ntlm.create_auth_request()
			})
			if resp == 407:
				dprint("Auth required")
				ntlm_challenge = ""
				for header in headers:
					if header[0] == "Proxy-Authenticate" and "NTLM" in header[1]:
						ntlm_challenge = header[1]
						break

				if ntlm_challenge:
					dprint("Challenged")
					try:
						ntlm_challenge = base64.decodebytes(ntlm_challenge.split()[1].encode("utf-8"))
					except:
						ntlm_challenge = base64.decodestring(ntlm_challenge.split()[1])
					resp, headers, body = self.do_socket({
						"Proxy-Authorization": "NTLM %s" % ntlm.create_challenge_response(ntlm_challenge)
					})

					return resp, headers, body
				else:
					dprint("Didn't get challenge, not NTLM proxy")
			elif resp > 400:
				return resp, None, None
			else:
				dprint("No auth required")

		return resp, headers, body

	def do_HEAD(self):
		dprint("Entering")

		self.do_GET()

		dprint("Done")

	def do_GET(self):
		dprint("Entering")

		resp, headers, body = self.do_transaction()
		if resp >= 400:
			dprint("Error %d" % resp)
			self.send_error(resp)
		else:
			self.fwd_resp(resp, headers, body)

		dprint("Done")

	def do_POST(self):
		dprint("Entering")

		self.do_GET()

		dprint("Done")

	def do_PUT(self):
		dprint("Entering")

		self.do_GET()

		dprint("Done")

	def do_DELETE(self):
		dprint("Entering")

		self.do_GET()

		dprint("Done")

	def do_PATCH(self):
		dprint("Entering")

		self.do_GET()

		dprint("Done")

	def do_CONNECT(self):
		dprint("Entering")

		resp, headers, body = self.do_transaction()
		if resp >= 400:
			dprint("Error %d" % resp)
			self.send_error(resp)
		else:
			dprint("Tunneling through proxy")
			self.send_response(200, "Connection established")
			self.send_header("Proxy-Agent", self.version_string())
			self.end_headers()

			rlist = [self.connection, self.client_socket]
			wlist = []
			count = 0
			while not EXIT:
				count += 1
				(ins, _, exs) = select.select(rlist, wlist, rlist, 1)
				if exs:
					break
				if ins:
					for i in ins:
						if i is self.client_socket:
							out = self.connection
						else:
							out = self.client_socket

						data = i.recv(4096)
						if data:
							out.send(data)
							count = 0
				if count == MAX_IDLE:
					break

		dprint("Done")

	def fwd_resp(self, resp, headers, body):
		dprint("Entering")
		self.send_response(resp)

		for header in headers:
			if header[0] != "Transfer-Encoding":
				dprint("Returning %s: %s" % (header[0], header[1]))
				self.send_header(header[0], header[1])

		self.end_headers()

		try:
			self.wfile.write(body)
		except:
			pass

		dprint("Done")

	def get_destination(self):
		if NOPROXY.size:
			netloc = self.path
			path = "/"
			if not self.command == "CONNECT":
				parse = urlparse.urlparse(self.path, allow_fragments=False)
				if parse.netloc:
					netloc = parse.netloc
				if not ":" in netloc:
					port = parse.port
					if not port:
						if parse.scheme == "http":
							port = 80
						elif parse.scheme == "https":
							port = 443
					netloc = netloc + ":" + str(port)

				path = parse.path
				if parse.params:
					path = path + ";" + parse.params
				if parse.query:
					path = path + "?" + parse.query

			try:
				spl = netloc.split(":", 1)
				addr = socket.getaddrinfo(spl[0], int(spl[1]))
				if len(addr) and len(addr[0]) == 5:
					ipport = addr[0][4]
					dprint("%s => %s + %s" % (self.path, ipport, path))
					
					if ipport[0] in NOPROXY:
						self.path = path
						return ipport
			except:
				traceback.print_exc(file=sys.stdout)
			
		return None

class PoolMixIn(socketserver.ThreadingMixIn):
	def process_request(self, request, client_address):
		self.pool.submit(self.process_request_thread, request, client_address)

class ThreadedTCPServer(PoolMixIn, socketserver.TCPServer):
	daemon_threads = True
	allow_reuse_address = True

	pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS)

def serve_forever(httpd):
	global EXIT

	print("Serving at %s:%d proc %s" % (LISTEN, PORT, multiprocessing.current_process().name))

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		dprint("Exiting")
		EXIT = True
	
	httpd.shutdown()

def start_worker(pipeout):
	parsecli()
	httpd = ThreadedTCPServer((LISTEN, PORT), Proxy, bind_and_activate=False)
	mainsock = socket.fromshare(pipeout.recv())
	httpd.socket = mainsock

	serve_forever(httpd)

def runpool():
	parsecli()

	try:
		httpd = ThreadedTCPServer((LISTEN, PORT), Proxy)
	except OSError as e:
		print(e)
		return
		
	mainsock = httpd.socket

	if hasattr(socket, "fromshare"):
		workers = MAX_WORKERS
		for i in range(workers-1):
			(pipeout, pipein) = multiprocessing.Pipe()
			p = multiprocessing.Process(target=start_worker, args=(pipeout,))
			p.daemon = True
			p.start()
			while p.pid == None:
				time.sleep(1)
			pipein.send(mainsock.share(p.pid))

	serve_forever(httpd)

def parseproxy(proxystr):
	global NTLM_PROXY

	NTLM_PROXY = proxystr.split(":")
	if len(NTLM_PROXY) == 1:
		NTLM_PROXY.append(80)
	else:
		NTLM_PROXY[1] = int(NTLM_PROXY[1])
	NTLM_PROXY = tuple(NTLM_PROXY)

def parsenoproxy(noproxy):
	global NOPROXY

	nops = [i.strip() for i in noproxy.split(",")]
	for nop in nops:
		if not nop:
			continue
		
		try:
			if "-" in nop:
				spl = nop.split("-", 1)
				ipns = netaddr.IPRange(spl[0], spl[1])
			elif "*" in nop:
				ipns = netaddr.IPGlob(nop)
			else:
				ipns = netaddr.IPNetwork(nop)
			NOPROXY.add(ipns)
		except:
			print("Bad noproxy IP definition")
			sys.exit()

def parsecli():
	global DEBUG
	global LISTEN
	global LOGGER
	global MAX_IDLE
	global MAX_WORKERS
	global PORT

	if os.path.exists(INI):
		config = configparser.ConfigParser()
		config.read(INI)

		if "proxy" in config.sections():
			if "server" in config.options("proxy"):
				server = config.get("proxy", "server").strip()
				if server:
					parseproxy(server)

			if "port" in config.options("proxy"):
				port = config.get("proxy", "port").strip()
				try:
					PORT = int(port)
				except:
					pass

			if "listen" in config.options("proxy"):
				listen = config.get("proxy", "listen").strip()
				if listen:
				    LISTEN = listen
				
			if "gateway" in config.options("proxy"):
				if config.get("proxy", "gateway") == "1":
					LISTEN = ''

			if "noproxy" in config.options("proxy"):
				parsenoproxy(config.get("proxy", "noproxy"))

		if "settings" in config.sections():
			if "workers" in config.options("settings"):
				workers = config.get("settings", "workers").strip()
				try:
					MAX_WORKERS = int(workers)
				except:
					pass

			if "threads" in config.options("settings"):
				threads = config.get("settings", "threads").strip()
				try:
					MAX_THREADS = int(threads)
				except:
					pass

			if "idle" in config.options("settings"):
				idle = config.get("settings", "idle").strip()
				try:
					MAX_IDLE = int(idle)
				except:
					pass

			if "log" in config.options("settings"):
				if config.get("settings", "log") == "1":
					LOGGER = Log("debug-%s.log" % multiprocessing.current_process().name, "w")
					DEBUG = True

	for i in range(len(sys.argv)):
		if "--proxy=" in sys.argv[i]:
			parseproxy(sys.argv[i].split("=")[1])
		elif "--noproxy=" in sys.argv[i]:
			parsenoproxy(sys.argv[i].split("=")[1])

	if "--debug" in sys.argv:
		LOGGER = Log("debug-%s.log" % multiprocessing.current_process().name, "w")
		DEBUG = True

	if NTLM_PROXY == None:
		print("No proxy defined")
		sys.exit()

def quit():
	mypid = os.getpid()
	for pid in sorted(psutil.pids(), reverse=True):
		if pid == mypid:
			continue

		try:
			p = psutil.Process(pid)
			if p.exe() == sys.executable:
				p.kill()
		except:
			pass

def handle_exceptions(type, value, tb):
	# Create traceback log
	list = traceback.format_tb(tb, None) + traceback.format_exception_only(type, value)
	tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % ("".join(list[:-1]), list[-1])
	
	if LOGGER != None:
		print(tracelog)
	else:
		sys.stderr.write(tracelog)

		# Save to debug.log
		dbg = open('debug-%s.log' % multiprocessing.current_process().name, 'w')
		dbg.write(tracelog)
		dbg.close()

if __name__ == "__main__":
	multiprocessing.freeze_support()
	sys.excepthook = handle_exceptions

	if "--quit" in sys.argv:
		quit()
	else:
		runpool()
