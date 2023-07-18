# fritz-tools

## Documentation
We recommend Freifunk-Communities to link to the following documentation instead of publishing their own Instructions to avoid fragmentation of useful Information. It does not contain Community-specific quirks.

 - [English](https://fritz-tools.readthedocs.io/en/latest/)
 - [German](https://fritz-tools.readthedocs.io/de/latest/)

## Basic Usage:

Download the needed images for your device and put them beside this script.

Using network autoconfiguration with privileges (uboot images must be in the same folder too):

```
wget https://downloads.openwrt.org/releases/22.03.5/targets/ipq40xx/generic/openwrt-22.03.5-ipq40xx-generic-avm_fritzbox-7530-initramfs-fit-uImage.itb
wget https://firmware.freifunk-aachen.de/firmware/download/from-2022.1.x/sysupgrade/gluon-ffac-v2022.1.14-1-avm-fritz-box-7530-sysupgrade.bin
wget https://downloads.openwrt.org/snapshots/targets/ipq40xx/generic/u-boot-fritz7530/uboot-fritz7530.bin
sudo python3 fritzflash.py --dev eno2 --initramfs ./openwrt-22.03.5-ipq40xx-generic-avm_fritzbox-7530-initramfs-fit-uImage.itb --sysupgrade ./gluon-ffac-v2022.1.14-1-avm-fritz-box-7530-sysupgrade.bin

sudo./fritzflash.py --dev eno2 --initramfs ./openwrt-22.03.0-ipq40xx-generic-avm_fritzrepeater-1200-initramfs-fit-uImage.itb --sysupgrade ./openwrt-22.03.3-ipq40xx-generic-avm_fritzrepeater-1200-squashfs-sysupgrade.bin
```

USing self configuration for other devices:

```
wget https://downloads.openwrt.org/releases/22.03.5/targets/ipq40xx/generic/openwrt-22.03.5-ipq40xx-generic-avm_fritzbox-4040-squashfs-eva.bin
wget https://downloads.openwrt.org/releases/22.03.5/targets/ipq40xx/generic/openwrt-22.03.5-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin
sudo ip a a 192.168.178.2/24 dev eno2
./fritzflash.py --dev eno2 --sysupgrade ./openwrt-22.03.5-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin
```

## Windows Usage

1. disable Wifi
2. allow incoming port 69/UDP or disable Firewall
3. run script as administrator, so that it can change the current ip address and open Port 69/UDP
4. enable Firewall
5. enable Wifi again

For other devices than the 7520/7530/1200, less privileges are needed (no TFTP) if the initial ip address is set manually in the network adapter configs.
