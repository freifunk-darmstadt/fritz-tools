#!/usr/bin/env python3
import argparse
import os
import socket
import time
import sys
from ftplib import FTP
from ipaddress import ip_address

AUTODISCOVER_TIMEOUT = 1
FTP_TIMEOUT = 2
FTP_MAX_RETRY = 10

MODELS = {
    "173": {
        "name": "FRITZ!WLAN Repeater 300E",
        "images": {
            "gluon": [
                "avm-fritz-wlan-repeater-300e-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz300e-squashfs-sysupgrade.bin"
            ],
        },
    },
    "200": {
        "name": "FRITZ!WLAN Repeater 450E",
        "images": {
            "gluon": [
                "avm-fritz-wlan-repeater-450e-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz450e-squashfs-sysupgrade.bin"
            ]
        },
    },
    "219": {
        "name": "FRITZ!Box 4020",
        "images": {
            "gluon": [
                "avm-fritz-box-4020-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz4020-squashfs-sysupgrade.bin",
                "avm_fritz4020-squashfs-sysupgrade.bin"
            ]
        },
    },
    "227": {
        "name": "FRITZ!Box 4040",
        "images": {
            "gluon": [
                "avm-fritz-box-4040-bootloader.bin"
            ],
            "openwrt": [
                "avm_fritzbox-4040-squashfs-eva.bin"
            ]
        },
    }
}


class FritzFTP(FTP):
    class ConnectionTimeout(Exception):
        pass

    def __init__(self, ipaddr, username='adam2', password='adam2', timeout=1, max_retry=0, retry_cb=None):
        trynum = 1
        while trynum <= max_retry:
            try:
                retry_cb(trynum, max_retry)
                super().__init__(ipaddr, user=username, passwd=password, timeout=timeout)
                break
            except socket.timeout:
                trynum += 1
            except OSError:
                time.sleep(1)
                trynum += 1
        if trynum > max_retry:
            raise FritzFTP.ConnectionTimeout()
        self.set_pasv(True)

    def getenv(self):
        env = [b'']
        fritzenv = {}

        def storeenv(x):
            env[0] += x

        self.voidcmd('MEDIA SDRAM')
        try:
            self.retrbinary('RETR env', storeenv)
        except socket.timeout:
            pass

        for line in env[0].decode('ascii').splitlines():
            key, value = line.split(maxsplit=1)
            fritzenv[key] = value

        return fritzenv

    def setenv(self, key, value):
        self.voidcmd('SETENV %s %s' % (key, value))

    def set_flash_timeout(self):
        self.sock.settimeout(60 * 5)

    def upload_image(self, image):
        self.set_flash_timeout()
        self.voidcmd('MEDIA FLSH')
        self.storbinary('STOR mtd1', image)

    def reboot(self):
        self.voidcmd('REBOOT')
        self.close()


def connection_refused_message():
    print("""\
    It seems you have a booted-up AVM device running in your Network.
    This might be because you missed the 10 second window after powering on your AVM device.
    In this case: Power cycle your device and retry.

    If this problem persists, make sure you have no connectin to other AVM equipment, for example via WLAN.
    """)


def step1_intro(device_ipaddr="192.168.178.1"):
    print("""\
Welcome to fritzflash!

## Intro

    This program will install OpenWrt, a widely used free and open source aftermarket firmware for wireless routers,
    onto your AVM device. You can always find the most recent version of this script in its Git repository:
    https://www.github.com/freifunk-darmstadt/fritz-tools

    It is strongly recommended to only connect your computer to the device you want to flash. The script sends broadcast
    packets via the default route to discover the address of the device to be flashed, so disable all other network
    connections (Ethernet, WLAN, WWAN) to make sure the packets are sent towards the correct interface!

    It might be helpful to connect both your computer and the AVM device through a switch, or else your computers
    network interface might not receive its configuration in time.

    Lets start by assigning your PC a static IP Address that is within the subnet of the device you want to flash.
    Apply the following configuration to your network interface connected to the AVM device:
    """)

    client_ip = str(ip_address(device_ipaddr) + 1)
    gateway = str(ip_address(device_ipaddr))

    print("""
        IP address:     %s
        Prefix Length:  24
        Netmask:        255.255.255.0
        Gateway:        %s
        DNS Servers:    None (blank)
        """ % (client_ip, gateway))

    print("""\
    Once you're done, press enter and power-cycle your AVM device by disconnecting and reconnecting the power-supply.""")
    input()


def step2_discovery(ipaddr=None, image=None, dump_env=False):
    print("""
## Discovery

    We now try to discover the IP address of your AVM device, please stand by... (Abort: Ctrl+c)
    """)

    if ipaddr:
        print("""\
        Static device ip given: %s""" % ipaddr)

    else:
        ipaddr = autodiscover_avm_ip()

        if not ipaddr:
            print("""
            Autodiscovery failed!
            Press any key to exit.
            """)
            input()
            sys.exit(1)

        print("""
        AVM device found at %s.""" % ipaddr)

    print("""
    Now we're trying to discover the model... (10 retries)
    """)

    env = get_env_from_device(ipaddr)
    if dump_env:
        import json
        with open("env.json", "w") as handle:
            json.dump(env, handle)
        print("""
    Environment was dumped to env.json.
        """)

    hwrev = env.get('HWRevision', None)
    if hwrev:
        print("""
        Model found: %s""" % MODELS[hwrev]['name'])
    else:
        print("""
    Autodiscovery failed to recognize the hardware!

    Open an issue at https://github.com/freifunk-darmstadt/fritz-tools/issues with model information for your device.
    Please also include the environment dump below:

    Environment:
    ============

    %s
        """ % env)

        sys.exit(1)

    print("""
    Next we try to find a matching image file in the local directory...
    """)
    if not image:
        filename, image = get_image(hwrev)
    else:
        filename = image
        image = open(image, 'rb')

    print("""\
        %s (%d kB)
    """ % (filename, os.path.getsize(filename) / 1024.0))

    return ipaddr, image

def step3_flash():
    print("""
## Flashing

    Writing OpenWrt image to your AVM device...
    This process may take a lot of time. Do *not* turn off the device!

    First, the device will erase it's current Operating System.
    Next, the device will write the Gluon image to it's memory.

    The red Info LED will illuminate in this step. Do not worry, this is expected behavior.

    Please be patient while we flash your AVM device, this may take a while.
    """)


def finish_message():
    print("""
    ## Finish

    Your device has been successfully flashed. The device will now reboot and should be
    reachable in a few minutes.

    Reconfigure your network interface to use DHCP and access your router's configuration at http://192.168.1.1
    in your web browser.
    """)


def retry_status(current_try, max_try):
    if current_try == 1:
        print('\t', end='')
    print(".", end='')
    sys.stdout.flush()


def autodiscover_avm_ip():
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.settimeout(1)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.settimeout(AUTODISCOVER_TIMEOUT)
    receiver.bind(('0.0.0.0', 5035))

    print('\t', end='')
    while True:
        try:
            sys.stdout.flush()
            receiver.sendto(b'aa', ("192.168.178.1", 5035))  # Dirty hack to add conntrack entry
            sender.sendto(bytearray.fromhex("0000120101000000c0a8b20100000000"), ('255.255.255.255', 5035))
            while 1:
                data, addr = receiver.recvfrom(64)
                if addr[0] == '192.168.178.1':
                    return addr[0]
        except socket.timeout:
            print(".", end='')
        except OSError as ex:
            print(ex, file=sys.stderr)
            time.sleep(1)
        except KeyboardInterrupt:
            print('\rAborting...\n')
            return


def determine_image_name(env_string):
    try:
        model = MODELS[env_string]
    except KeyError:
        return

    image_names = []
    for names in model['images'].values():
        try:
            image_names.extend(names)
        except KeyError:
            pass

    return image_names


def get_env_from_device(ipaddr):
    try:
        session = FritzFTP(str(ipaddr), timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status)
        env = session.getenv()
        session.close()
    except FritzFTP.ConnectionTimeout:
        print("Unable to connect to your AVM device (Maximum number of retries exceeded).")
        sys.exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        sys.exit(1)

    return env


def get_image(hwrev):
    image_names = determine_image_name(hwrev)

    if not image_names:
        print("""
        No image names found for %s

        Press any key to exit.
        """ % MODELS[hwrev]['name'])
        input()
        sys.exit(1)

    dir_content = os.listdir(os.getcwd())
    files = []
    for file in dir_content:
        cwd = os.getcwd()
        file = os.path.join(cwd, file)
        if not os.path.isfile(file):
            continue
        for image_name in image_names:
            if image_name in file:
                files.append(file)

    if len(files) > 1:
        print("""
        Multiple matching image files found, specify one via the --image parameter.""")

        for file in files:
            print("\t%s" % file)

        print("""
        Press any key to exit.""")
        input()
        sys.exit(1)

    elif not files:
        print("""
        No matching image found in the local directory.
        Please download one or specify one via the --image parameter.

        Press any key to exit
        """)
        input()
        sys.exit(1)

    return files[0], open(files[0], 'rb')


def perform_flash(ipaddr, file):
    print("-> Establishing connection to device!")

    try:
        session = FritzFTP(ipaddr, timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status)
    except FritzFTP.ConnectionTimeout:
        print("-> Max retries exceeded! Check connection and try again.")
        print("Press any key to exit.")
        input()
        sys.exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        print("Press any key to exit.")
        input()
        sys.exit(1)

    print("-> Flash image")
    flash_message()
    session.upload_image(file)
    print("-> Image write successful")
    print("-> Performing reboot")
    session.reboot()
    finish_message()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Flash OpenWrt images to AVM devices via the EVA bootloader.')
    parser.add_argument(
        '--ip', type=ip_address, help='IP Address of target device (disables autodiscovery of IP adddress)')
    parser.add_argument(
        '--image', type=str, help='Path to image file')
    parser.add_argument(
        '--dumpenv', action='store_true', help='Fetch environment and dump to env.json'
    )
    args = parser.parse_args()

    imagefile = None
    if args.image:
        try:
            imagefile = open(args.image, 'rb')
        except FileNotFoundError:
            print("Image file \"%s\" does not exist!" % os.path.abspath(args.image_path))
            sys.exit(1)

    step1_intro()

    ipaddr, image = step2_discovery(ipaddr=args.ip, image=args.image, dump_env=args.dumpenv)

    step3_flash(ipaddr, image)
