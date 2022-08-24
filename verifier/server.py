from wptserve.utils import isomorphic_decode, isomorphic_encode
from urllib.parse import parse_qs
from urllib.parse import urlparse
import json
import ssl, websocket, asyncio


GLOBALS = {'uuid' : "", "stash" : ""}

def update_globals(parsed_req):
    global GLOBALS

    for g in GLOBALS.keys():
        if g in parsed_req:
            GLOBALS[g] = parsed_req[g][0]

"""
TODO:
1. get response
2. create filename (method.proto.domain.port.corr)
  - filter the domain until ".test"
3. parse content by "\n\n" to separate the header from the body (should work, if not, adapt the verifier)
4. split each header by ":" and add response header
"""

def calculate_sw_filename(request):
    query = parse_qs(urlparse(request.url).query)

    domain = request.url_parts.netloc.split(":")[0]
    port = int(request.url_parts.netloc.split(":")[1])
    scheme = request.url_parts.scheme

    filename = f"{scheme}.{domain}.{port}_sw"

    return filename

def caulculate_filename(request):
    query = parse_qs(urlparse(request.url).query)

    domain = request.url_parts.netloc.split(":")[0]
    port = int(request.url_parts.netloc.split(":")[1])
    scheme = request.url_parts.scheme
    resource = None
    try :
      resource = query['res'][0]
    except:
      pass

    filename = f"{request.method}.{scheme}.{domain}.{port}.{resource if resource else ''}"


    return filename

def build_response(response, headers, body):
  headers = json.loads(headers)

  response.code = int(headers['code'])

  for k in headers['headers']:
    if headers['headers'][k]:
      response.headers.append(k.encode(), headers['headers'][k].encode())
  
  response.content = body
  
  # lines = resp.split("\n")

  # code = int(lines[0].split(" ")[1])

  # head, body = resp.split("\n\n")

  # if len(head) > 1:
  #   head = head.split("\n")[1:]
  
  # for l in head:
  #   key, value = l.split(":")[0], "".join(l.split(":")[1:]) # in case there are more :'s, like in a url for example
  #   response.headers.append(key.encode(), value.encode())

  # response.code = code
  # response.content = body

  # print("[+]", response, response.headers, response.code, response.content)
  return response

# def on_error(ws, error):
#     print("ON ERROR", error)


def stash_add(uuid, data):
	try:
		url = "wss://web-platform.test:8666/stash_responder_blocking"
		ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		# localhost_pem = pathlib.Path().with_name("localhost.pem")
		cert_path = "../tools/certs/cacert.pem"
		ssl_context.load_verify_locations(cert_path)
		# print(dir(ssl_context))
		ws = websocket.create_connection(url, sslopt={'context' : ssl_context}) #sslopt={"cert_reqs": ssl.CERT_NONE})
		# ws = websocket.create_connection(url, sslopt={"cert_reqs": ssl.CERT_NONE})
		print(ws)

		ws.send(json.dumps({'action': 'set', 'key': uuid, 'value': data}, separators=(',', ':')))

		# websocket

		# print("SENDING TO WSS")

		# async with websockets.connect(url, ssl=ssl_context) as websocket:
		# 	a = await websocket.send()
		# 	print("websocket send result", a)
	except Exception as e:
		print("oops", e)


def main(request, response):
	print("request", request)
	
	query = parse_qs(urlparse(request.url).query)
	if 'sw' in query:
		# asking for the service worker registratin
		filename = calculate_sw_filename(request)
		print("IN A SW REQUEST", filename)
		with open(f"verifier/responses/{filename}.html", "r") as f:
			response.content = f.read()

		response.headers.append(b"Content-Type", b"text/html; charset=utf-8")
		return


	# if 'echo' in query and query['echo'][0] == 'csp':
	# 	csp = request.headers.get(b'content-security-policy', None)

	# 	response.headers.append(b"Content-Type", b"text/html; charset=utf-8")
	# 	# allow the script to read the response text
	# 	response.headers.append(b'Access-Control-Allow-Origin:', b'*')
	# 	# reply with the csp in the body
	# 	response.content = csp

	# 	return	

	# if it is not an echo request, proceed as usual
	filename = caulculate_filename(request)
	print("fname", filename)

	headers = None
	body = None
	try:
		with open(f"verifier/responses/{filename}.headers", "r") as f:
			headers = f.read()

		with open(f"verifier/responses/{filename}.body", "r") as f:
			body = f.read()

		with open(f"verifier/responses/{filename}.ver", "r") as f:
			uuid = f.read().strip()

		build_response(response, headers, body)

		try:
			stash_add(uuid, filename)
			# asyncio.run(stash_add(uuid, filename))
		except Exception as e:
			print("aaah...", e)
		# try:
		# 	print(request.server)
		# 	print(request.server.stash)
		# 	print("DIR", request.server.config)
		# 	print("Addr", request.server.stash.manager.address)
		# 	print("Addr", request.server.stash.manager.get_dict())
		# 	print("Addr", request.server.stash.manager.shared_data)
		# 	print("QUEUE", request.server.stash.get_queue)
		# 	print(uuid)
		# 	# request.server.stash.put(uuid, filename)
		# except Exception as e:
		# 	print("aaah..", e)

		return
	except:
		response.code = 500