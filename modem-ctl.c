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
0. finish I9250 loader
1. integrate with libsamsung-ipc @ replicant/FSO
2. nvdata checking/regeneration
#endif

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

fail:
	return ret;
}
