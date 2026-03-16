#!/usr/bin/env python3
"""portscanner - Simple TCP port scanner."""
import socket, argparse, sys, concurrent.futures, time

COMMON_PORTS = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
    110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',
    995:'POP3S',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',
    6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'
}

def scan_port(host, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            try: banner = s.recv(1024).decode(errors='replace').strip()[:60]
            except: banner = ''
            s.close()
            return (port, True, banner)
        s.close()
    except: pass
    return (port, False, '')

def parse_ports(spec):
    ports = set()
    for part in spec.split(','):
        if '-' in part:
            a, b = part.split('-', 1)
            ports.update(range(int(a), int(b)+1))
        elif part.lower() == 'common':
            ports.update(COMMON_PORTS.keys())
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    p = argparse.ArgumentParser(description='TCP port scanner')
    p.add_argument('host')
    p.add_argument('-p', '--ports', default='common', help='Ports: 80,443 or 1-1024 or common')
    p.add_argument('-t', '--timeout', type=float, default=1.0)
    p.add_argument('-w', '--workers', type=int, default=50)
    p.add_argument('--banner', action='store_true', help='Grab banners')
    args = p.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
        print(f"Scanning {args.host} ({ip})")
    except socket.gaierror:
        print(f"Cannot resolve: {args.host}"); sys.exit(1)

    ports = parse_ports(args.ports)
    print(f"Ports: {len(ports)} | Timeout: {args.timeout}s | Workers: {args.workers}\n")
    
    start = time.time()
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_port, ip, port, args.timeout): port for port in ports}
        for f in concurrent.futures.as_completed(futures):
            port, is_open, banner = f.result()
            if is_open:
                service = COMMON_PORTS.get(port, '?')
                line = f"  {port:<6} open   {service}"
                if args.banner and banner:
                    line += f"  [{banner}]"
                print(line)
                open_ports.append(port)

    elapsed = time.time() - start
    print(f"\n{len(open_ports)} open / {len(ports)} scanned in {elapsed:.1f}s")

if __name__ == '__main__':
    main()
