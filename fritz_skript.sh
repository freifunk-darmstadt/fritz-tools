!/bin/sh
# usage: fritz_skript.sh eno2
#set -e
dev="$1"

ip a a 192.168.178.2/24 dev $dev

python3 ./fritzflash.py

ip a d 192.168.178.2/24 dev $dev
ip a a 192.168.1.70/24 dev $dev

echo "openwrt should be flashed to RAM"
echo "did set ip address - wait 30s for reboot"
sleep 30

echo "reboot should have happened waiting for openwrt in RAM"

while ! ping -c 1 -w 1 192.168.1.1 > /dev/null 2>&1; do
	echo "wait 1 second"
	sleep 1
done

echo "host online - write firmware to flash"
sleep 20

SCP="scp -O -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostkeyAlgorithms=+ssh-rsa"

$SCP ./uboot-fritz7530.bin root@192.168.1.1:/tmp
$SCP ./firmware.bin root@192.168.1.1:/tmp

$SSH root@192.168.1.1 "mtd write /tmp/uboot-fritz7530.bin uboot0 && mtd write /tmp/uboot-fritz7530.bin uboot1"
$SSH root@192.168.1.1 "ubirmvol /dev/ubi0 --name=avm_filesys_0 && ubirmvol /dev/ubi0 --name=avm_filesys_1"
$SSH root@192.168.1.1 "sysupgrade -n /tmp/firmware.bin"
echo "success"