#! /usr/bin/env python3
import argparse
import ipaddress
from ipaddress import (
    IPv4Interface,
    IPv4Address,
    IPv6Interface,
    IPv6Address,
    AddressValueError,
)
import platform
import socket
import time
from ftplib import FTP
from pathlib import Path
from subprocess import run
from contextlib import contextmanager

from typing import List, ContextManager, Union

from simple_tftp import serve_file

IPInterface = Union[IPv4Interface, IPv6Interface]
IPAddress = Union[IPv4Address, IPv6Address]

AUTODISCOVER_TIMEOUT = 1
FTP_TIMEOUT = 2
FTP_MAX_RETRY = 10

INITRAMFS_BOOT_TIMEOUT = 180  # in seconds
IS_POSIX = platform.system() in ["Linux", "Darwin", "FreeBSD"]


class FritzFTP(FTP):
    class ConnectionTimeout(Exception):
        pass

    def __init__(
        self,
        ip,
        username="adam2",
        password="adam2",
        timeout=1,
        max_retry=0,
        retry_cb=None,
    ):
        i = 1
        while i <= max_retry:
            try:
                retry_cb(i, max_retry)
                super().__init__(ip, user=username, passwd=password, timeout=timeout)
                break
            except socket.timeout:
                i += 1
            except OSError as e:
                time.sleep(1)
                i += 1
        if i > max_retry:
            raise FritzFTP.ConnectionTimeout()
        self.set_pasv(True)

    def getenv(self):
        env = [b""]
        fritzenv = {}

        def storeenv(x):
            env[0] += x

        self.voidcmd("MEDIA SDRAM")
        try:
            self.retrbinary("RETR env", storeenv)
        except socket.timeout:
            pass

        for line in env[0].decode("ascii").splitlines():
            l = line.split()
            if len(l) < 2:
                print(f"'{l}' is not a tuple, ignoring")
                # after using the fritz recovery tool, my FB7530 had
                # a ['ptest'] entry, without a value..
                continue
            fritzenv[l[0]] = l[1]

        return fritzenv

    def set_flash_timeout(self):
        self.sock.settimeout(60 * 5)

    def upload_image(self, image):
        self.set_flash_timeout()
        self.voidcmd("MEDIA FLSH")
        with image.open("rb") as file:
            self.storbinary("STOR mtd1", file)

    def reboot(self):
        self.voidcmd("REBOOT")
        self.close()


@contextmanager
def set_ip(ipinterface: IPInterface, network_device: str) -> ContextManager[None]:
    if IS_POSIX:
        output = run(
            ["ip", "addr", "add", ipinterface.with_prefixlen, "dev", network_device],
            capture_output=True,
        )
        try:
            yield output.returncode in [0, 2]
        finally:
            run(
                [
                    "ip",
                    "addr",
                    "delete",
                    ipinterface.with_prefixlen,
                    "dev",
                    network_device,
                ],
                capture_output=True,
            )
    else:
        output = run(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "address",
                f'"{network_device}" {ipinterface} {ipinterface.netmask}',
            ],
            capture_output=True,
        )
        try:
            yield output.returncode == 0
        finally:
            run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "delete",
                    "address",
                    f'"{network_device}" {ipinterface}',
                ],
                capture_output=True,
            )


def await_online(host: IPAddress):
    response = run(["ping", "-c", "1", "-W", f"{INITRAMFS_BOOT_TIMEOUT}", str(host)])
    return response.returncode


def scp_legacy_check() -> bool:
    """Since OpenSSH release 9.0, scp uses the sftp protocol by default which
    is known to be incompatible with the uboot present on stock 7530/7520"""
    response = run(["ssh", "-V"], capture_output=True)
    version_string = response.stderr.decode().strip()
    ssh_ver, ssl_ver = version_string.split(",")
    ssh_ver = ssh_ver.strip("OpenSSH_")
    return ssh_ver >= "9.0"


def ssh(host: IPAddress, cmd: List[str], user: str = "root"):
    null_file = "/dev/null" if IS_POSIX else "NUL"
    args = [
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        f"UserKnownHostsFile={null_file}",
        "-o",
        "HostKeyAlgorithms=+ssh-rsa",
    ]
    run(["ssh", *args, f"{user}@{host}", *cmd]).check_returncode()


def scp(host: IPAddress, file: Path, user: str = "root", target: Path = "/tmp/"):
    null_file = "/dev/null" if IS_POSIX else "NUL"
    args = ["-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={null_file}"]
    if scp_legacy_check():
        args.append("-O")
    run(["scp", *args, file.name, f"{user}@{host}:{target}"]).check_returncode()


def connection_refused_message():
    print(
        "\nIt seems you have a booted-up AVM device running in your Network.\n"
        "This might be because you missed the 10 second window after powering on your AVM device.\n"
        "In this case: Powercycle your device and retry.\n"
        "If this problem persits, check if you might have connections to another AVM device, e.g. via WiFi/WLAN.\n\n"
    )


def start_message(ip_address):
    print(
        "This program will help you installing OpenWRT or Gluon, a widely used Firmware for Freifunk networks, onto your AVM device.\n"
        "You can always find the most current version of this script at https://www.github.com/freifunk-darmstadt/fritz-tools\n\n"
        "It is strongly recommended to only connect your computer to the device you want to flash.\n"
        "Try to disable all other connections (Ethernet, WiFi/WLAN, VMs) if detection fails.\n"
        "Sometimes an unmanaged switch between your AVM device and your computer is helpful.\n\n"
        "If you run this program with according permission, it will configure IPs on your host automatically.\n"
        "Otherwise, make sure you have assigned your PC a static IP Address in the Subnet of the device you want to flash.\n"
        "The following example would be a completely fine option:\n"
    )
    print("IP-Address: %s" % str(ipaddress.ip_address(ip_address) + 1))
    print("Subnet: 255.255.255.0")
    print("Gateway: %s" % str(ipaddress.ip_address(ip_address)))
    print("DNS Servers: Leave blank\n")
    print(
        "Once you're ready to flash, press enter, disconnect power from your AVM device and reconnect the power-supply."
    )


def connect_message():
    print("We will now connect to your devices bootloader.")


def flash_message():
    print(
        "\nWriting Gluon image to your AVM device...\n"
        "This process may take a lot of time.\n\n"
        "First, the device will erase its current Operating System.\n"
        "Next, the device will write the Gluon image to its memory.\n"
        "The red Info LED will illuminate in this step. Don't worry, this is expected behavior.\n\n"
        "Do *not* turn off the device!\n\n"
        "We will tell you when your device has finished installing Gluon (this may take a while)."
    )


def finish_message():
    print(
        "\n== Congratulations! ==\n\n"
        "Your device is now running Gluon.\n"
        "It will restart and in 2-5 minutes you will be able to visit its config-mode.\n"
        "Remember to reconfigure your interface to automatically obtain an IP-address!\n"
        "You can reach config-mode by typing in http://192.168.1.1/ in your preferred Webbrowser.\n"
    )
    print("Press any key to exit.")
    input()


def retry_status(current_try, max_try):
    print("--> Try %d of %d" % (current_try, max_try))


def autodiscover_avm_ip():
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.bind(("192.168.178.2", 0))
    except OSError as e:
        if e.errno == 99:
            print("\rIP address 192.168.178.2 is not configured on any interface.")
            exit(1)
        else:
            raise e from None
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.settimeout(1)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.settimeout(AUTODISCOVER_TIMEOUT)
    receiver.bind(("192.168.178.2", 5035))

    i = 1
    while True:
        try:
            print("\rTry %d..." % i, end="")
            receiver.sendto(
                b"aa", ("192.168.178.1", 5035)
            )  # Dirty hack to add conntrack entry
            sender.sendto(
                bytearray.fromhex("0000120101000000c0a8b20100000000"),
                ("255.255.255.255", 5035),
            )
            while 1:
                data, addr = receiver.recvfrom(64)
                if addr[0] == "192.168.178.1":
                    print("\rFritzBox found at %s" % addr[0])
                    return addr[0]
        except socket.timeout:
            i += 1
        except OSError:
            i += 1
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("\rAborting...\n")
            return None

    return None


def determine_image_name(env_string):
    models = {
        "172": {
            "gluon": ["avm-fritz-box-7320-sysupgrade.bin"],
            "openwrt": ["avm_fritz7320-squashfs-sysupgrade.bin"],
        },
        "173": {
            "gluon": ["avm-fritz-wlan-repeater-300e-sysupgrade.bin"],
            "openwrt": ["fritz300e-squashfs-sysupgrade.bin"],
        },
        "179": {
            "gluon": ["avm-fritz-box-7330-sysupgrade.bin"],
            "openwrt": ["avm_fritz7320-squashfs-sysupgrade.bin"],
        },
        "181": {
            "gluon": ["avm-fritz-box-7360-sl-sysupgrade.bin"],
            "openwrt": ["avm_fritz7360sl-squashfs-sysupgrade.bin"],
        },
        "183": {
            "gluon": ["avm-fritz-box-7360-v1-sysupgrade.bin"],
            "openwrt": ["avm_fritz7360sl-squashfs-sysupgrade.bin"],
        },
        "188": {
            "gluon": ["avm-fritz-box-7330-sl-sysupgrade.bin"],
            "openwrt": ["avm_fritz7320-squashfs-sysupgrade.bin"],
        },
        "189": {
            "gluon": ["avm-fritz-box-7312-sysupgrade.bin"],
            "openwrt": ["avm_fritz7312-squashfs-sysupgrade.bin"],
        },
        "196": {
            "gluon": ["avm-fritz-box-7360-v2-sysupgrade.bin"],
            "openwrt": ["avm_fritz7360sl-squashfs-sysupgrade.bin"],
        },
        "200": {
            "gluon": ["avm-fritz-wlan-repeater-450e-sysupgrade.bin"],
            "openwrt": ["fritz450e-squashfs-sysupgrade.bin"],
        },
        "219": {
            "gluon": ["avm-fritz-box-4020-sysupgrade.bin"],
            "openwrt": [
                "fritz4020-squashfs-sysupgrade.bin",
                "avm_fritz4020-squashfs-sysupgrade.bin",
            ],
        },
        "227": {
            "gluon": ["avm-fritz-box-4040-bootloader.bin"],
            "openwrt": ["avm_fritzbox-4040-squashfs-eva.bin"],
        },
        "203": {
            "openwrt": [
                "openwrt-lantiq-xrx200-avm_fritz7362sl-initramfs-kernel.bin"
            ]
        },
        "209": {
            "openwrt": ["openwrt-lantiq-xrx200-avm_fritz7412-initramfs-kernel.bin"]
        },
        "218": {
            "openwrt": ["openwrt-lantiq-xrx200-avm_fritz7430-initramfs-kernel.bin"]
        },
        "236": {"openwrt": ["uboot-fritz7530.bin"]},
        "244": {"openwrt": ["uboot-fritz1200.bin"]},
        "247": {
            # fritzbox 7520
            "openwrt": ["uboot-fritz7530.bin"]
        },
    }
    for model in models.keys():
        if model == env_string:
            image_names = []
            if "gluon" in models[model]:
                image_names += models[model]["gluon"]
            if "openwrt" in models[model]:
                image_names += models[model]["openwrt"]
            return image_names
    return None


def autoload_image(ip):
    print("\nStarting automatic image-selection!")
    print("-> Establishing connection to device!")

    try:
        ftp = FritzFTP(
            ip, timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status
        )
    except FritzFTP.ConnectionTimeout:
        print("-> Max retrys exceeded! Check connection and try again.")
        exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        exit(1)

    env = ftp.getenv()
    ftp.close()

    if "HWRevision" not in env:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> No model saved on device!")
        exit(1)

    image_names = determine_image_name(env["HWRevision"])

    if image_names is None:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> Unknown Model %s!" % env["HWRevision"])
        print("Press any key to exit.")
        input()
        exit(1)

    cwd = Path()
    files = []
    for file in cwd.iterdir():
        if not file.is_file():
            continue
        for image_name in image_names:
            if image_name in file.name:
                files.append(file)

    if len(files) > 1:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> Multiple potential image files found!")
        for file in files:
            print("--> %s" % file)
        print("\nPlease specify the image via `--image` parameter.")
        print("Press any key to exit.")
        input()
        exit(1)

    if not files:
        print("\nAutomatic image-selection unsuccessful!")
        print("--> No potential image file found!")
        print("\nPlease download and specify the image via `--image` parameter.")
        print("Press any key to exit.")
        input()
        exit(1)

    print("-> Automatic image-selection successful!")
    print("--> Will flash %s" % files[0])

    return files[0], env["HWRevision"]


def perform_flash(ip, file):
    print("-> Establishing connection to device!")

    try:
        ftp = FritzFTP(
            ip, timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status
        )
    except FritzFTP.ConnectionTimeout:
        print("-> Max retries exceeded! Check connection and try again.")
        print("Press any key to exit.")
        input()
        exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        print("Press any key to exit.")
        input()
        exit(1)

    print("-> Flash image")

    if file.name in [
        "uboot-fritz7520.bin",
        "uboot-fritz7530.bin",
        "uboot-fritz1200.bin",
        "openwrt-lantiq-xrx200-avm_fritz7412-initramfs-kernel.bin",
        "openwrt-lantiq-xrx200-avm_fritz7362sl-initramfs-kernel.bin",
        "openwrt-lantiq-xrx200-avm_fritz7430-initramfs-kernel.bin",
    ]:
        size = file.stat().st_size
        assert size < 0x2000000

        if file.name in [
            "uboot-fritz7520.bin",
            "uboot-fritz7530.bin",
            "uboot-fritz1200.bin",
        ]:
            addr = size
            haddr = 0x85000000
        else:
            addr = (0x8000000 - size) & ~0xFFF
            haddr = 0x80000000 + addr
        with file.open("rb") as img:
            # The following parameters allow booting the avm recovery system with this
            # script.
            if file.name in [
                "openwrt-lantiq-xrx200-avm_fritz7412-initramfs-kernel.bin",
                "openwrt-lantiq-xrx200-avm_fritz7430-initramfs-kernel.bin",
            ]:
                ftp.voidcmd("SETENV linux_fs_start 0")
            ftp.voidcmd("SETENV memsize 0x%08x" % (addr))
            ftp.voidcmd("SETENV kernel_args_tmp mtdram1=0x%08x,0x88000000" % (haddr))
            ftp.voidcmd("MEDIA SDRAM")
            ftp.storbinary("STOR 0x%08x 0x88000000" % (haddr), img)
    else:
        flash_message()
        ftp.upload_image(file)
        print("-> Image write successful")
        print("-> Performing reboot")
        ftp.reboot()


def perform_bootloader_flash(
    sysupgradefile: Path,
    imagefile: Path = None,
    flash_tftp: bool = None,
):
    with set_ip(ipaddress.ip_interface("192.168.1.70/24"), args.device) as can_set_ip:
        if not can_set_ip:
            print("could not set ip to 192.168.1.70/24")
            print("make sure to run with admin privileges")
            exit(1)
        target_host = ipaddress.ip_address("192.168.1.1")
        print("Waiting for Host to come up with IP Adress 192.168.1.1 ...")
        await_online(target_host)
        print("-> Host online.\nTransfering sysupgrade target firmware")
        scp(target_host, sysupgradefile)
        if flash_tftp:
            print("-> Transfering bootloader")
            scp(target_host, imagefile)
            print("Writing Bootloader")
            ssh(
                target_host,
                [
                    "mtd",
                    "write",
                    f"/tmp/{imagefile}",
                    "uboot0",
                    "&&",
                    "mtd",
                    "write",
                    f"/tmp/{imagefile}",
                    "uboot1",
                ],
            )
            ssh(
                target_host,
                [
                    "ubirmvol",
                    "/dev/ubi0",
                    "--name=avm_filesys_0",
                    "&&",
                    "ubirmvol",
                    "/dev/ubi0",
                    "--name=avm_filesys_1",
                ],
            )
        print("Executing Sysupgrade")
        ssh(target_host, ["sysupgrade", "-n", f"/tmp/{sysupgradefile.name}]"])


def perform_tftp_flash(initramfsfile: Path, sysupgradefile: Path):
    with set_ip(ipaddress.ip_interface("192.168.1.70/24"), args.device) as can_set_ip:
        if not can_set_ip:
            print("could not set ip to 192.168.1.70/24")
            print(
                "make sure to run with admin privileges and that the ip is currently unset"
            )
            exit(1)
        success = False
        while not success:
            success, host = next(serve_file(initramfsfile))
        print(f"-> Transfered initramfs image to {host}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Flash Gluon image to AVM devices using EVA or/and TFTP."
    )
    parser.add_argument(
        "--ip", type=str, help="IP Address of device. Autodiscovery if not specified."
    )
    parser.add_argument(
        "--image",
        type=str,
        help="(uboot) image file to transfer. Autodiscovery if not specified.",
    )
    parser.add_argument(
        "--initramfs",
        type=str,
        help="Compatible openwrt initramfs image file for uboot+TFTP flash.",
    )
    parser.add_argument(
        "--sysupgrade",
        type=str,
        help="Target system image file, the operating system for TFTP flash.",
    )
    parser.add_argument(
        "--device",
        "-dev",
        type=str,
        help="Name of the Ethernet adapter (look it up ie by 'ip link')",
        required=True,
    )
    args = parser.parse_args()

    flash_tftp = False
    ramfsfile = None
    sysupgradefile = None
    imagefile = None
    if args.image:
        imagefile = Path(args.image)
        if not imagefile.is_file():
            print(f'Image file "{imagefile.absolute()}" does not exist!')
            exit(1)
        print("If this device is a FB 7520/7530 or a FR 1200 write y")
        flash_tftp = input().lower().startswith("y")

    start_message("192.168.178.1")
    input()

    with set_ip(ipaddress.ip_interface("192.168.178.2/24"), args.device) as can_set_ip:
        if can_set_ip:
            print("did set ip to 192.168.178.2/24")
        else:
            print("could not set ip to 192.168.178.2/24")

        if args.ip:
            try:
                ip = ipaddress.ip_address(args.ip)
            except AddressValueError:
                print(f"{args.ip} is not a valid IPv4 address!")
                exit(1)
        else:
            print("Trying to autodiscover! Abort via Ctrl-c.")
            ip = autodiscover_avm_ip()

            if ip is None:
                print("\nAutodiscovery failed!")
                print("Press any key to exit.")
                input()
                exit(1)

            print("\nAutodiscovery succesful!")
            print(f"-> Device detected at {ip}.")

        if args.image is None:
            # Try to automatically locate an image to use
            imagefile, hwrevision = autoload_image(ip)
            flash_tftp = hwrevision in ["236", "244", "247"]

        if flash_tftp:
            if not (args.initramfs and args.sysupgrade):
                print("Providing initramfs and sysupgrade is required for this device")
                exit(1)
            ramfsfile = Path(args.initramfs)
            sysupgradefile = Path(args.sysupgrade)
            if not ramfsfile.is_file():
                print(f'File "{ramfsfile.absolute()}" does not exist!')
                print("Please check file name and Path.")
                exit(1)
            if not sysupgradefile.is_file():
                print(f'File "{sysupgradefile.absolute()}" does not exist!')
                print("Please check file name and Path.")
                exit(1)

        perform_flash(ip, imagefile)

    if flash_tftp:
        print("Starting TFTP flash process for FB 7530/7520 or FR 1200")
        perform_tftp_flash(args.initramfs, args.sysupgrade)
        print("Sleep 90s - let system boot")
        time.sleep(60)
        print("Device will come up for ~5s about now, but we still need to wait 30s")
        time.sleep(30)
    perform_bootloader_flash(sysupgradefile, imagefile, flash_tftp)
    print("Finished flash procedure")
    finish_message()
