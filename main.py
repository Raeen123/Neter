from scapy.all import ARP, Ether, srp
from netaddr import IPNetwork
import subprocess
from mac_vendor_lookup import MacLookup
from prettytable import PrettyTable
from requests import get
import socket
from pyfiglet import Figlet, main
from click import echo, style


def main():
    banner = Figlet(font="slant")
    banner_txt = banner.renderText("NETER")
    echo(style(banner_txt, fg='blue'))
    echo(style("\n 1 : gateway \n 2 : maclookup \n 3 : scanner \n 4 : speedtest \n 5 : ip \n 6 : passwords \n \n ", fg='green'))
    main2()


def main2():
    num = int(input(style("ENTER YOUR NUMBER : ", fg='blue')))
    while num is None or num > 6:
        echo(style("Error", fg='red'))
        num = input(style("ENTER YOUR NUMBER : ", fg='blue'))
    if num == 1:
        gateway()
    elif num == 2:
        maclookup()
    elif num == 3:
        scanner()
    elif num == 4:
        speedtest()
    elif num == 5:
        ip()
    elif num == 6:
        passwords()

    again = str(input(style("\n Do you want to exit ? [y/n]", fg='red')))
    if again == 'n':
        main2()


def gateway_re():
    ipconfig = subprocess.check_output(
        ['ipconfig']).decode('utf-8').split('\n')
    ip = (((ipconfig[-2]).split(':'))[1])[1:-1]
    mask = (((ipconfig[-3]).split(':'))[1])[1:-1]
    return(str(IPNetwork(f"{ip}/{mask}").cidr))


def gateway():
    print("IP and NET MASK : "+gateway_re())


def maclookup(macAddress):
    """
        Mac lookup <macAddress>
    """
    try:
        return(MacLookup().lookup(macAddress))
    except:
        return("Error")


def scanner():
    """
       Scan your network and find users
    """
    target_ip = gateway_re()
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    t = PrettyTable(['IP', 'MAC', 'MAC LOOKUP'])
    for client in clients:
        mac = client['mac']
        t.add_row([client['ip'], mac, maclookup(mac)])
    print(t)


def speedtest():
    """
       Get Ping / Download / Upload
    """
    test = subprocess.check_output(['speedtest']).decode('utf-8').split('\n')
    print(test[1]+"\n\n"+test[4]+"\n\n"+test[6]+"\n\n"+test[8])


def ip():
    """
       Get local and public ip
    """
    ipV4 = get('https://api.ipify.org').text
    ipV6 = get('https://api64.ipify.org').text
    print("\nPUBLICK IP VERSION 4 : " + ipV4)
    if ipV4 != ipV6:
        print("\nPUBLIC IP VERSION 6 : " + ipV6)
    localIP = socket.gethostbyname(socket.gethostname())
    print("\nLOCAL IP : " + localIP)


def passwords():
    """
       Get your WiFi password
    """
    t = PrettyTable(['WIFI NAME', 'PASSWORD'])
    data = subprocess.check_output(
        ['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
    for i in profiles:
        results = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
        results = [b.split(":")[1][1:-1]
                   for b in results if "Key Content" in b]
        try:
            t.add_row([i, results[0]])
        except IndexError:
            t.add_row([i, ""])
    print(t)


if __name__ == "__main__":
    main()
