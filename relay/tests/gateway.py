"""Místní náhrada brány Supabase: /rest/v1/* -> PostgREST (jen pro testy)."""
import http.server
import sys
import urllib.error
import urllib.request

UPSTREAM = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3010"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.startswith("/rest/v1/"):
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        headers = {k: v for k, v in self.headers.items() if k.lower() in ("content-type", "accept", "prefer")}
        request = urllib.request.Request(UPSTREAM + self.path[len("/rest/v1"):], data=body, headers=headers, method="POST")
        try:
            with OPENER.open(request, timeout=30) as response:
                status, data, ctype = response.status, response.read(), response.headers.get("Content-Type")
        except urllib.error.HTTPError as error:
            status, data, ctype = error.code, error.read(), error.headers.get("Content-Type")
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy %s\n" % (fmt % args))


http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
