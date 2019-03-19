from libraries import *

def vender_finding(mac_adr):
    mac_url = 'http://macvendors.co/api/%s'
    vender = (requests.get(mac_url % mac_adr))
    response_dict = json.loads(json.dumps(vender.json()))
    return response_dict['result']['company']

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clents_list = []
    for element in answered_list:
        try:
            company = vender_finding(element[1].hwsrc)
        except Exception:
            company = 'Not Available'
        clent_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "vender": company}
        clents_list.append(clent_dict)
        print(clents_list)
    return clents_list

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip, target_mac):
    # target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4)

def default_int_details():
    myiface = netifaces.gateways()
    default_gate = myiface['default'][netifaces.AF_INET][0]
    myiface = myiface['default'][netifaces.AF_INET][1]
    addrs = netifaces.ifaddresses(myiface)

    # Get ipv4 stuff
    ipinfo = addrs[socket.AF_INET][0]
    address = ipinfo['addr']
    netmask = ipinfo['netmask']
    broadcast = ipinfo['broadcast']
    macaddress = (str(addrs[netifaces.AF_LINK][0])[11:28])

    # Create ip object and get
    cidr = netaddr.IPNetwork(address + '/' + netmask).prefixlen
    cidr = str(address) + '/' + str(cidr)

    interfaces = get_windows_if_list()
    for interface in interfaces:
        if str(interface["guid"]) == str(myiface):
            netid = (interface["name"])
            break

    returndict = {
        "interface": myiface,
        "address": address,
        "netmask": netmask,
        "cidr": cidr,
        "broadcast": broadcast,
        "macaddress": macaddress,
        "netid": netid,
        "default": default_gate
    }
    return returndict

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def sniff():
    int = default_int_details()['netid']
    scapy.sniff(iface = int, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("Arp Spoofing Attack Detected")
                print("Attackers MAC: " + response_mac + ' ' + vender_finding(response_mac))
                default_gate = default_int_details()["default"]
                my_ip = default_int_details()["address"]
                restore(my_ip, default_gate)
                restore(default_gate, my_ip)
        except IndexError:
            pass

def arp_avoider():
    x = Thread(target=sniff, args=())
    print(str(x) + 'for arp_avoider')
    x.setDaemon(True)
    x.start()
