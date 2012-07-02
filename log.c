/*
 * log.c: Log debug macros for the Firmware Loader
 * This file is part of:
 *
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

#include "log.h"

void hexdump(void* data, size_t size) {
	if (size < 1) {
		return;
	}
	char *_data = (char*)data;
	char __hd_buf[DUMP_SIZE * 3 + 1];

	size_t len = size < DUMP_SIZE ? size : DUMP_SIZE;
	memset(__hd_buf, 0, sizeof(__hd_buf));
	int i;
	for (i = 0; i < len; i++) {
		snprintf(__hd_buf + i * 3, 4, "%02x ", _data[i]);	
	}

	__hd_buf[sizeof(__hd_buf) - 1] = '\0';
	_d("%s", __hd_buf);
}
