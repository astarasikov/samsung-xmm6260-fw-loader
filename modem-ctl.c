/*
 * Firmware loader for Samsung I9100 and I9250
 * Copyright (C) 2012 Alexander Tarasikov <alexander.tarasikov@gmail.com>
 *
 * based on the incomplete C++ implementation which is
 * Copyright (C) 2012 Sergey Gridasov <grindars@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "modemctl_common.h"

#if 0
TODO:
0. add write fd select waiting, look into freezes
1. integrate with libsamsung-ipc @ replicant/FSO
2. nvdata checking/regeneration

nonblocking io
static buffers
select fd fix
link online polling
nvram md5
ramdump
#endif

#if 0
<7>[   25.670997] [MIF] IPC-TX(14): 

	[
		7f HDLC_START
			0c 00 length
			00 unknown
			[
				09 00 raw length 
				01 mseq
				00 aseq
				01 group [PWR]
				07 index
				01 type [EXEC]
				02 02 [IPC_PWR_PHONE_STATE_NORMAL]
			]
		7e HDLC_END
	] 14 bytes

<7>[   25.681167] [MIF] IPC-RX(374): 7f 0f 00 00 0c 00 ff 01 80 01 02 01 07 01 00 80 ...

#endif

static int test_ipc(void) {
	int ipc_fd = -1;
	int rfs_fd = -1;
	
	ipc_fd = open("/dev/umts_ipc0", O_RDWR);
	
	if (ipc_fd < 0) {
		_e("failed to open ipc socket");
		goto fail;
	}

	rfs_fd = open("/dev/umts_rfs0", O_RDWR);
	if (rfs_fd < 0) {
		_e("failed to open rfs socket");
		goto fail;
	}

	char buffer[128] = {
		0x09, 0x00, 0x02, 0x00,
		0x01, 0x07, 0x01, 0x02,
		0x02, 0xf4, 0x19, 0x40,
		0xe8, 0xa1, 0x02, 0x00
	};
#if 0

	int ret = write(ipc_fd, buffer, 16);
	_d(">>> ret %d", ret);

	ret = receive(ipc_fd, buffer, 128);
	_d("<<< ret %d", ret);

	hexdump(buffer, 128);
#endif

	usleep(1000 * 1000);

fail:
	if (ipc_fd >= 0) {
		close(ipc_fd);
	}

	if (rfs_fd >= 0) {
		close(rfs_fd);
	}

	return -1;
}

int main(int argc, char** argv) {
	int ret;

	if (argc > 1) {
		ret = boot_modem_i9100();
	}
	else {
		ret = boot_modem_i9250();
	}

	if (ret < 0) {
		_e("failed to boot modem");
		goto fail;
	}
	else {
		_d("done loading firmware");
	}

	test_ipc();

fail:
	return ret;
}
