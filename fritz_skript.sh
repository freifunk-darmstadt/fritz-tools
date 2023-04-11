#!/bin/sh
# usage: fritz_skript.sh eno2
set -e
dev="$1"

ip a a 192.168.178.2/24 dev $dev

python3 ./fritzflash.py

sleep 300

ip a d 192.168.178.2/24 dev $dev
ip a a 192.168.1.2/24 dev $dev

while ! ping -c 1 -w 1 192.168.1.1 > /dev/null 2>&1; do
	echo "wait 1 second"
	sleep 1
done

sleep 1

SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

$SCP ./uboot-fritz7530.bin root@192.168.1.1:/tmp
$SCP ./avm_fritzbox-7530-squashfs-sysupgrade.bin root@192.168.1.1:/tmp

$SSH -c root@192.168.1.1 "mtd write /tmp/uboot-fritz7530.bin uboot0 && mtd write /tmp/uboot-fritz7530.bin uboot1"
$SSH -c root@192.168.1.1 "ubirmvol /dev/ubi0 --name=avm_filesys_0 && ubirmvol /dev/ubi0 --name=avm_filesys_1"
$SSH -c root@192.168.1.1 "sysupgrade -n /tmp/avm_fritzbox-7530-squashfs-sysupgrade.bin

