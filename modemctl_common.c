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

//modemctl shared code
#include "modemctl_common.h"

/*
 * modemctl generic functions
 */
int modemctl_link_set_active(fwloader_context *ctx, bool enabled) {
	unsigned status = enabled;
	int ret;
	unsigned long ioctl_code;

	ioctl_code = IOCTL_LINK_CONTROL_ACTIVE;
	ret = c_ioctl(ctx->link_fd, ioctl_code, &status);

	if (ret < 0) {
		_d("failed to set link active to %d", enabled);
		goto fail;
	}

	return 0;
fail:
	return ret;
}

int modemctl_link_set_enabled(fwloader_context *ctx, bool enabled) {
	unsigned status = enabled;
	int ret;
	unsigned long ioctl_code;

	ioctl_code = IOCTL_LINK_CONTROL_ENABLE;
	ret = c_ioctl(ctx->link_fd, ioctl_code, &status);

	if (ret < 0) {
		_d("failed to set link state to %d", enabled);
		goto fail;
	}

	return 0;
fail:
	return ret;
}

int modemctl_wait_link_ready(fwloader_context *ctx) {
	int ret;

	struct timeval tv_start = {};
	struct timeval tv_end = {};

	gettimeofday(&tv_start, 0);;

	//link wakeup timeout in milliseconds
	long diff = 0;

	do {
		ret = c_ioctl(ctx->link_fd, IOCTL_LINK_CONNECTED, 0);
		if (ret < 0) {
			goto fail;
		}

		if (ret == 1) {
			return 0;
		}

		usleep(LINK_POLL_DELAY_US);
		gettimeofday(&tv_end, 0);;

		diff = (tv_end.tv_sec - tv_start.tv_sec) * 1000;
		diff += (tv_end.tv_usec - tv_start.tv_usec) / 1000;
	} while (diff < LINK_TIMEOUT_MS);

	ret = -ETIMEDOUT;
	
fail:
	return ret;
}

int modemctl_wait_modem_online(fwloader_context *ctx) {
	int ret;

	struct timeval tv_start = {};
	struct timeval tv_end = {};

	gettimeofday(&tv_start, 0);;

	//link wakeup timeout in milliseconds
	long diff = 0;

	do {
		ret = c_ioctl(ctx->boot_fd, IOCTL_MODEM_STATUS, 0);
		if (ret < 0) {
			goto fail;
		}

		if (ret == STATE_ONLINE) {
			return 0;
		}

		usleep(LINK_POLL_DELAY_US);
		gettimeofday(&tv_end, 0);;

		diff = (tv_end.tv_sec - tv_start.tv_sec) * 1000;
		diff += (tv_end.tv_usec - tv_start.tv_usec) / 1000;
	} while (diff < LINK_TIMEOUT_MS);

	ret = -ETIMEDOUT;
	
fail:
	return ret;
}

int modemctl_modem_power(fwloader_context *ctx, bool enabled) {
	if (enabled) {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_ON, 0);
	}
	else {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_OFF, 0);
	}
	return -1;
}

int modemctl_modem_boot_power(fwloader_context *ctx, bool enabled) {
	if (enabled) {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_BOOT_ON, 0);
	}
	else {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_BOOT_OFF, 0);
	}
	return -1;
}

unsigned char calculateCRC(void* data, size_t offset, size_t length)
{
	unsigned char crc = 0;
	unsigned char *ptr = (unsigned char*)(data + offset);
	
	while (length--) {
		crc ^= *ptr++;
	}

	return crc;
}

