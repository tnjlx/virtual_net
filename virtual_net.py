# 网络模拟器：模拟网络环境，主要用于分析样本的网络行为 - Python3
# openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
import os
import sys
import json
import socketserver
import threading
import time
import dnslib
from http import server
from http.server import BaseHTTPRequestHandler
import ssl
import logging
import csv
klog = logging.getLogger("klog")
klog.setLevel(logging.DEBUG)
ksh = logging.StreamHandler(stream=open("run.log", "a", encoding="utf8"))
ksh_std = logging.StreamHandler(stream=sys.stdout)
ksh.setFormatter(logging.Formatter(fmt="[%(asctime)s][%(filename)s line:%(lineno)d][%(levelname)s]: %(message)s"))
ksh_std.setFormatter(logging.Formatter(fmt="[%(asctime)s][%(filename)s line:%(lineno)d][%(levelname)s]: %(message)s"))
klog.addHandler(ksh)
klog.addHandler(ksh_std)

# 配置文件
with open("config.json", "r", encoding="utf8") as gfr:
    config = json.load(gfr)

# DNS库和响应文件
dns_db = {}
with open(config["dns_dbfile"], "r", encoding="utf8") as gfr:
    for line in csv.reader(gfr):
        dns_db[line[0]] = line[1]
with open(config["tcp_file"], "rb") as gfr:
    tcp_con = gfr.read()
with open(config["http_file"], "rb") as gfr:
    http_con = gfr.read()
with open(config["https_file"], "rb") as gfr:
    https_con = gfr.read()


class MDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            dnsrecord = dnslib.DNSRecord.parse(self.request[0])
            dnsrecord.header.set_qr(dnslib.QR.RESPONSE)
            qname = str(dnsrecord.q.qname).rstrip('.')
            ipaddress = dns_db[qname] if qname in dns_db else config["dns_default_ip"]
            klog.info([self.client_address, "DNS", qname, ipaddress])
            dnsrecord.add_answer(dnslib.RR(qname, dnslib.QTYPE.A, rdata=dnslib.A(ipaddress)))
            self.request[1].sendto(dnsrecord.pack(), self.client_address)
        except Exception as e:
            pass


class MTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            klog.info([self.client_address, "TCP"])
            self.request[1].sendto(tcp_con, self.client_address)
        except Exception as e:
            pass


class MHTTPRequestHandler(BaseHTTPRequestHandler):
    def send_content(self, page, status):
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    # 处理GET请求
    def do_GET(self):
        klog.info([self.client_address, "HTTP_GET", self.requestline, str(self.headers)])
        self.send_content(http_con, 200)

    # 处理POST请求
    def do_POST(self):
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        klog.info([self.client_address, "HTTP_POST", self.requestline, str(self.headers), post_body])
        self.send_content(http_con, 200)


    # 处理PUT请求
    def do_PUT(self):
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        klog.info([self.client_address, "HTTP_PUT", self.requestline, str(self.headers), post_body])
        self.send_content(http_con, 200)


class MHTTPSRequestHandler(BaseHTTPRequestHandler):
    def send_content(self, page, status):
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    # 处理GET请求
    def do_GET(self):
        klog.info([self.client_address, "HTTPS_GET", self.requestline, str(self.headers)])
        self.send_content(https_con, 200)

    # 处理POST请求
    def do_POST(self):
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        klog.info([self.client_address, "HTTPS_POST", self.requestline, str(self.headers), post_body])
        self.send_content(https_con, 200)

    # 处理PUT请求
    def do_PUT(self):
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        klog.info([self.client_address, "HTTPS_PUT", self.requestline, str(self.headers), post_body])
        self.send_content(https_con, 200)


def main():
    klog.info("开始创建DNS服务")
    dns_server = socketserver.UDPServer((config["ip_server_dns"], config["dns_port"]), MDNSHandler)
    threading.Thread(target=dns_server.serve_forever).start()
    klog.info("开始创建TCP服务")
    tcp_server = socketserver.TCPServer((config["ip_server"], config["tcp_port"]), MTCPHandler)
    threading.Thread(target=tcp_server.serve_forever).start()
    klog.info("开始创建HTTP服务")
    http_server = server.HTTPServer((config["ip_server"], config["http_port"]), MHTTPRequestHandler)
    threading.Thread(target=http_server.serve_forever).start()
    klog.info("开始创建HTTPS服务")
    https_server = server.HTTPServer((config["ip_server"], config["https_port"]), MHTTPSRequestHandler)
    if config["ssl_version"] == "tls10":
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config["https_certfile"], config["https_keyfile"])
    https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
    threading.Thread(target=https_server.serve_forever).start()
    klog.info("服务创建完成，进入无限循环")
    while True:
        time.sleep(1000 * 60)


if __name__ == "__main__":
    os.chdir(sys.path[0])
    main()
