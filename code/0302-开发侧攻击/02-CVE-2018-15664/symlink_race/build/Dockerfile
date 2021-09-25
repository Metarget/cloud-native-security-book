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

# Build the binary.
FROM opensuse/tumbleweed
RUN zypper in -y gcc glibc-devel-static
RUN mkdir /builddir
COPY symlink_swap.c /builddir/symlink_swap.c
RUN gcc -Wall -Werror -static -o /builddir/symlink_swap /builddir/symlink_swap.c

# Set up our malicious rootfs.
FROM opensuse/tumbleweed
ARG SYMSWAP_TARGET=/w00t_w00t_im_a_flag
ARG SYMSWAP_PATH=/totally_safe_path
RUN echo "FAILED -- INSIDE CONTAINER PATH" >"$SYMSWAP_TARGET"
COPY --from=0 /builddir/symlink_swap /symlink_swap
ENTRYPOINT ["/symlink_swap"]
