from wptserve.utils import isomorphic_decode, isomorphic_encode
from urllib.parse import parse_qs
from urllib.parse import urlparse

# élève.
utf8_subdomain = b"Domain=\xC3\xA9\x6C\xC3\xA8\x76\x65."

resp1 = """
<!doctype html>
<html>
<meta charset=utf-8>


<body>
	<iframe src="server.py?id=2&uuid={}&stash={}"></iframe>
    
</body>
</html>					
"""

resp2 = """
<!DOCTYPE html>
<html>
<body>
  <div>Loaded</div>
	<script src="{}"></script>
</body>
</html>					
"""

GLOBALS = {'uuid' : "", "stash" : ""}

def update_globals(parsed_req):
    global GLOBALS

    for g in GLOBALS.keys():
        if g in parsed_req:
            GLOBALS[g] = parsed_req[g][0]

def main(request, response):
    parsed_req = parse_qs(urlparse(request.url).query)
    req_id = parsed_req['id'][0]

    update_globals(parsed_req)

    if req_id == '1':
      # set script-src to none
        response.status = 200
        response.headers.append(b"Content-Type", b"text/html; charset=utf-8")
        response.headers.append(b"Content-Security-Policy", b"script-src 'none'")
        response.content = resp1.format(GLOBALS['uuid'], GLOBALS['stash'])
    elif req_id == '2':
        # set script-src to origin_3
        response.status = 200
        response.headers.append(b"Content-Type", b"text/html; charset=utf-8")
        response.headers.append(b"Content-Security-Policy", b"script-src http://www1.web-platform.test:8000")
        response.content = resp2.format("http://www1.web-platform.test:8000/tinker/csp/script.js");

    return
