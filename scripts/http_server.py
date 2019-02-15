from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingTCPServer

page = """
<html>
<header><title>This is title</title></header>
<body>
Hello world
</body>
</html>
"""


class DemoHttpRequestHandler(SimpleHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Connection', 'close')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(page.encode('utf-8'))


if __name__ == '__main__':
    try:
        httpd = ThreadingTCPServer(('127.0.0.1', 8080), DemoHttpRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('httpd exits.')
