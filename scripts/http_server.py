# 1.
#
# current device 192.168.43.24
#
# httpd 192.168.43.24:8080
# enter 192.168.43.24:8080 in chrome on current device
# Packets are captured via localhost instead of wlan
#
# 2.
#
# current device 192.168.43.24
# httpd 192.168.43.24:8080
# enter 192.168.43.24:8080 in chrome on another device
# Packets are captured via wlan
#
# 3.
#
# current device 192.168.43.24
# httpd 192.168.43.24:8080
# python socket 127.0.0.1:44444
# Packets are captured via localhost
#
#

from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingTCPServer

import sys

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
    address = ('127.0.0.1', 8080)

    if len(sys.argv) > 1 and ':' in sys.argv[1]:
        address = sys.argv[1].split(':')
        address = (address[0], int(address[1]))

    print("Listening on", address)

    try:
        httpd = ThreadingTCPServer(address, DemoHttpRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('httpd exits.')
