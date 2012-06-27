/*
 * log.h: Log debug macros for the Firmware Loader
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

#ifndef __LOG_H__
#define __LOG_H__

#include "common.h"

#ifndef SILENT
	#define LOG_TAG "xmm6260-sec"
	#define _p(fmt, x...) \
		do {\
			printf("[" LOG_TAG "]: " fmt " at %s:%s:%d\n", \
				##x, __FILE__, __func__, __LINE__); \
		} while (0)
#else
	#define _p(fmt, x...) do {} while (0)
#endif

#ifdef DEBUG
	#define _d(fmt, x...) _p("D/" fmt, ##x)
#else
	#define _d(fmt, x...) do {} while (0)
#endif

#define _e(fmt, x...) _p("E/" fmt, ##x)
#define _i(fmt, x...) _p("I/" fmt, ##x)

#define DUMP_SIZE 16

void hexdump(void* data, size_t size);

#endif //__LOG_H__
