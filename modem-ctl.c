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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

//for timeval
#include <sys/time.h>

//for mmap
#include <sys/mman.h>
#include <sys/stat.h>

#include "modem_prj.h"

#if 0
TODO:

1. I9100/I9250 detection (probe)
2. I9250 firmware offsets
3. integrate with libsamsung-ipc @ replicant/FSO

#endif

/*
 * IO helper functions
 */

#define DEBUG 1

#ifndef SILENT
	#define LOG_TAG "xmm6260-sec"
	#define _p(fmt, x...) \
		do {\
			printf("[" LOG_TAG "]: " fmt "\n", ##x); \
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
static char __hd_buf[DUMP_SIZE * 3 + 1];

static inline void hexdump(char* data, size_t size) {
	if (size < 1) {
		return;
	}

	size_t len = size < DUMP_SIZE ? size : DUMP_SIZE;
	memset(__hd_buf, 0, sizeof(__hd_buf));
	for (int i = 0; i < len; i++) {
		snprintf(__hd_buf + i * 3, 4, "%02x ", data[i]);	
	}

	__hd_buf[sizeof(__hd_buf) - 1] = '\0';
	_d("%s", __hd_buf);
}

static int c_ioctl(int fd, unsigned long code, void* data) {
	int ret;

	if (!data) {
		ret = ioctl(fd, code);
	}
	else {
		ret = ioctl(fd, code, data);
	}

	if (ret < 0) {
		_e("ioctl fd=%d code=%lx failed: %s", fd, code, strerror(errno));
	}
	else {
		_d("ioctl fd=%d code=%lx OK", fd, code);
	}

	return ret;
}

static inline int read_select(int fd, unsigned timeout) {
	struct timeval tv = {
		tv.tv_sec = timeout / 1000,
		tv.tv_usec = 1000 * (timeout % 1000),
	};

	fd_set read_set;
	FD_ZERO(&read_set);
	FD_SET(fd, &read_set);

	return select(fd + 1, &read_set, 0, 0, &tv);
}

static inline int receive(int fd, void *buf, size_t size) {
	int ret;
	if ((ret = read_select(fd, 0)) < 0) {
		_e("%s: failed to select the fd %d", __func__, fd);
		return ret;
	}
	else {
		_d("%s: selected fd %d for %d", __func__, ret, fd);
	}

	return read(fd, buf, size);
}

static int expect_data(int fd, void *data, size_t size) {
	int ret;
	char buf[size];
	if ((ret = receive(fd, buf, size)) < 0) {
		_e("failed to receive data");
		return ret;
	}
	ret = memcmp(buf, data, size);
	hexdump(buf, size);

	return ret;
}

/*
 * I9100 specific implementation
 */
#define MODEM_DEVICE(x) ("/dev/" #x)
#define LINK_PM MODEM_DEVICE(link_pm)
#define MODEM_DEV MODEM_DEVICE(modem_br)
#define BOOT_DEV MODEM_DEVICE(umts_boot0)
#define IPC_DEV MODEM_DEVICE(umts_ipc0)
#define RFS_DEV MODEM_DEVICE(umts_rfs0)

#define RADIO_IMAGE "/dev/block/mmcblk0p8"
#define NVDATA_IMAGE "/efs/nv_data.bin"

#define I9100_EHCI_PATH "/sys/devices/platform/s5p-ehci/ehci_power"


#define RADIO_MAP_SIZE (16 << 20)

/*
 * Components of the Samsung XMM6260 firmware
 */
enum xmm6260_image {
	PSI,
	EBL,
	SECURE_IMAGE,
	FIRMWARE,
	NVDATA,
};

/*
 * Locations of the firmware components in the Samsung firmware
 */
static struct xmm6260_offset {
	size_t offset;
	size_t length;
} i9100_radio_parts[] = {
	[PSI] = {
		.offset = 0,
		.length = 0xf000,
	},
	[EBL] = {
		.offset = 0xf000,
		.length = 0x19000,
	},
	[SECURE_IMAGE] = {
		.offset = 0x9ff800,
		.length = 0x800,
	},
	[FIRMWARE] = {
		.offset = 0x28000,
		.length = 0x9d8000,
	},
	[NVDATA] = {
		.offset = 0x6406e00,
		.length = 2 << 20,
	}
};

/*
 * Bootloader control interface definitions
 */

enum xmm6260_boot_cmd {
	SetPortConf        = 0x86,

	ReqSecStart        = 0x204,
	ReqSecEnd          = 0x205,
	ReqForceHwReset    = 0x208,

	ReqFlashSetAddress = 0x802,
	ReqFlashWriteBlock = 0x804
};

#define XMM_PSI_MAGIC 0x30

typedef struct {
	uint8_t magic;
	uint16_t length;
	uint8_t padding;
} __attribute__((packed)) psi_header_t;

typedef struct {
	uint8_t data[76];
} __attribute__((packed)) boot_info_t;

typedef struct {
	uint16_t check;
	uint16_t cmd;
	uint32_t data_size;
} __attribute__((packed)) bootloader_cmd_t;

typedef struct {
	int link_fd;
	int boot_fd;

	int radio_fd;
	char *radio_data;
	struct stat radio_stat;
} fwloader_context;

static int i9100_ehci_setpower(bool enabled) {
	int ret;
	
	_d("%s: enabled=%d", __func__, enabled);
	
	int ehci_fd = open(I9100_EHCI_PATH, O_RDWR);
	if (ehci_fd < 0) {
		_e("failed to open EHCI fd");
		goto fail;
	}
	else {
		_d("opened EHCI %s: fd=%d", I9100_EHCI_PATH, ehci_fd);
	}

	ret = write(ehci_fd, enabled ? "1" : "0", 1);

	//must write exactly one byte
	if (ret <= 0) {
		_e("failed to set EHCI power");
	}
	else {
		_d("set EHCI power");
	}

fail:
	if (ehci_fd >= 0) {
		close(ehci_fd);
	}

	return ret;
}

static int i9100_link_set_active(fwloader_context *ctx, bool enabled) {
	unsigned status = enabled;
	int ret;
	unsigned long ioctl_code;

	ioctl_code = IOCTL_LINK_CONTROL_ENABLE;
	ret = c_ioctl(ctx->link_fd, ioctl_code, &status);

	if (ret < 0) {
		_d("failed to set link state to %d", enabled);
		goto fail;
	}

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

static int i9100_wait_link_ready(fwloader_context *ctx) {
	int ret;

	while (1) {
		ret = c_ioctl(ctx->link_fd, IOCTL_LINK_CONNECTED, 0);
		if (ret < 0) {
			goto fail;
		}

		if (ret == 1) {
			break;
		}

		usleep(50 * 1000);
	}
	
	return 0;

fail:
	return ret;
}

static int xmm6260_setpower(fwloader_context *ctx, bool enabled) {
	if (enabled) {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_ON, 0);
	}
	else {
		return c_ioctl(ctx->boot_fd, IOCTL_MODEM_OFF, 0);
	}
	return -1;
}

static unsigned char calculateCRC(void* data,
	size_t offset, size_t length)
{
	unsigned char crc = 0;
	unsigned char *ptr = (unsigned char*)(data + offset);
	
	while (length--) {
		crc ^= *ptr++;
	}

	return crc;
}

static int send_image(fwloader_context *ctx, enum xmm6260_image type) {
	int ret;
	size_t length = i9100_radio_parts[PSI].length;
	size_t offset = i9100_radio_parts[PSI].offset;

	size_t start = offset;
	size_t end = length + start;

	//dump some image bytes
	_d("image start");
	hexdump(ctx->radio_data + start, length);

	while (start < end) {
		ret = write(ctx->boot_fd, ctx->radio_data + start, end - offset);
		if (ret < 0) {
			_d("failed to write image chunk");
			goto fail;
		}
		start += ret;
	}

	unsigned char crc = calculateCRC(ctx->radio_data, offset, length);
	
	if ((ret = write(ctx->boot_fd, &crc, 1)) < 1) {
		_d("failed to write CRC");
		goto fail;
	}

	return 0;

fail:
	return ret;
}

static int send_PSI(fwloader_context *ctx) {
	size_t length = i9100_radio_parts[PSI].length;

	psi_header_t hdr = {
		.magic = XMM_PSI_MAGIC,
		.length = length,
		.padding = 0xff,
	};
	int ret = -1;
	
	if ((ret = write(ctx->boot_fd, &hdr, sizeof(hdr))) != sizeof(hdr)) {
		_d("%s: failed to write header, ret %d", __func__, ret);
		goto fail;
	}

	if ((ret = send_image(ctx, PSI)) < 0) {
		_e("failed to send PSI image");
		goto fail;
	}

	for (int i = 0; i < 22; i++) {
		char ack;
		if (receive(ctx->boot_fd, &ack, 1) < 1) {
			_d("failed to read ACK byte %d", i);
			goto fail;
		}
		_d("%02x ", ack);
	}

	if ((ret = expect_data(ctx->boot_fd, "\x1", 1)) < 0) {
		_d("failed to wait for first ACK");
		goto fail;
	}

	if ((ret = expect_data(ctx->boot_fd, "\x1", 1)) < 0) {
		_d("failed to wait for second ACK");
		goto fail;
	}
	
	if ((ret = expect_data(ctx->boot_fd, "\x00\xaa", 2)) < 0) {
		_e("failed to receive PSI ACK");
		goto fail;
	}
	else {
		_d("received PSI ACK");
	}

	return 0;

fail:
	return ret;
}

static int send_EBL(fwloader_context *ctx) {
	int ret;
	int fd = ctx->boot_fd;
	unsigned length = i9100_radio_parts[PSI].length;

	if ((ret = write(fd, &length, sizeof(length))) < 0) {
		_e("failed to write EBL length");
		goto fail;
	}

	if ((ret = expect_data(fd, "\xcc\xcc", 2)) < 0) {
		_e("failed to wait for EBL header ACK");
	}
	
	if ((ret = send_image(ctx, EBL)) < 0) {
		_e("failed to send EBL image");
		goto fail;
	}
	
	if ((ret = expect_data(fd, "\x51\xa5", 2)) < 0) {
		_e("failed to wait for EBL image ACK");
	}

	return 0;

fail:
	return ret;
}

static int send_SecureImage(int fd) {
	return -1;
}

static int reboot_modem(fwloader_context *ctx, bool hard) {
	int ret;
	/*
	 * Disable the hardware to ensure consistent state
	 */
	if (hard) {	
		if ((ret = xmm6260_setpower(ctx, false)) < 0) {
			_e("failed to disable xmm6260 power");
			goto fail;
		}
		else {
			_d("disabled xmm6260 power");
		}
	}

	if ((ret = i9100_link_set_active(ctx, false)) < 0) {
		_e("failed to disable I9100 HSIC link");
		goto fail;
	}
	else {
		_d("disabled I9100 HSIC link");
	}

	if ((ret = i9100_ehci_setpower(false)) < 0) {
		_e("failed to disable I9100 EHCI");
		goto fail;
	}
	else {
		_d("disabled I9100 EHCI");
	}

	/*
	 * Now, initialize the hardware
	 */

	if ((ret = i9100_link_set_active(ctx, true)) < 0) {
		_e("failed to enable I9100 HSIC link");
		goto fail;
	}
	else {
		_d("enabled I9100 HSIC link");
	}

	if ((ret = i9100_ehci_setpower(true)) < 0) {
		_e("failed to enable I9100 EHCI");
		goto fail;
	}
	else {
		_d("enabled I9100 EHCI");
	}

	if (hard) {
		if ((ret = xmm6260_setpower(ctx, true)) < 0) {
			_e("failed to enable xmm6260 power");
			goto fail;
		}
		else {
			_d("enabled xmm6260 power");
		}
	}

	if ((ret = i9100_wait_link_ready(ctx)) < 0) {
		_e("failed to wait for link to get ready");
		goto fail;
	}
	else {
		_d("link ready");
	}
	
fail:
	return ret;
}

int main(int argc, char** argv) {
	int ret;
	fwloader_context ctx;
	memset(&ctx, 0, sizeof(ctx));

	ctx.radio_fd = open(RADIO_IMAGE, O_RDONLY);
	if (ctx.radio_fd < 0) {
		_e("failed to open radio firmware");
		goto fail;
	}
	else {
		_d("opened radio image %s, fd=%d", RADIO_IMAGE, ctx.radio_fd);
	}

	if (fstat(ctx.radio_fd, &ctx.radio_stat) < 0) {
		_e("failed to stat radio image, error %s", strerror(errno));
		goto fail;
	}

	ctx.radio_data = mmap(0, RADIO_MAP_SIZE, PROT_READ, MAP_SHARED,
		ctx.radio_fd, 0);
	if (ctx.radio_data == MAP_FAILED) {
		_e("failed to mmap radio image, error %s", strerror(errno));
		goto fail;
	}

	ctx.boot_fd = open(BOOT_DEV, O_RDWR);
	if (ctx.boot_fd < 0) {
		_e("failed to open boot device");
		goto fail;
	}
	else {
		_d("opened boot device %s, fd=%d", BOOT_DEV, ctx.boot_fd);
	}

	ctx.link_fd = open(LINK_PM, O_RDWR);
	if (ctx.link_fd < 0) {
		_e("failed to open link device");
		goto fail;
	}
	else {
		_d("opened link device %s, fd=%d", LINK_PM, ctx.link_fd);
	}

	if (reboot_modem(&ctx, true)) {
		_e("failed to hard reset modem");
	}
	else {
		_d("modem hard reset done");
	}

	/*
	 * Now, actually load the firmware
	 */
	if (write(ctx.boot_fd, "ATAT", 4) != 4) {
		_e("failed to write ATAT to boot socket");
		goto fail;
	}
	else {
		_d("written ATAT to boot socket, waiting for ACK");
	}
	
	usleep(500 * 1000);

	char buf[2];
	if (receive(ctx.boot_fd, buf, 1) < 0) {
		_e("failed to receive bootloader ACK");
		goto fail;
	}
	if (receive(ctx.boot_fd, buf + 1, 1) < 0) {
		_e("failed to receive chip IP ACK");
		goto fail;
	}
	_i("receive ID: [%02x %02x]", buf[0], buf[1]);

	if ((ret = send_PSI(&ctx)) < 0) {
		_e("failed to upload PSI");
		goto fail;
	}
	else {
		_d("PSI download complete");
	}

	if ((ret = send_EBL(&ctx)) < 0) {
		_e("failed to upload EBL");
		goto fail;
	}
	else {
		_d("EBL download complete");
	}

	if ((ret = send_SecureImage(ctx.boot_fd)) < 0) {
		_e("failed to upload Secure Image");
		goto fail;
	}
	else {
		_d("Secure Image download complete");
	}

	if (reboot_modem(&ctx, false)) {
		_e("failed to soft reset modem");
	}
	else {
		_d("modem soft reset done");
	}

fail:
	if (ctx.radio_data != MAP_FAILED) {
		munmap(ctx.radio_data, RADIO_MAP_SIZE);
	}

	if (ctx.link_fd >= 0) {
		close(ctx.link_fd);
	}

	if (ctx.radio_fd >= 0) {
		close(ctx.radio_fd);
	}

	if (ctx.boot_fd >= 0) {
		close(ctx.boot_fd);
	}

	return 0;
}
