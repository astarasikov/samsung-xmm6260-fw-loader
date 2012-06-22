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

#include "common.h"
#include "log.h"
#include "io_helpers.h" 

//Samsung IOCTLs
#include "modem_prj.h"

#if 0
TODO:

1. I9100/I9250 detection (probe)
2. I9250 firmware offsets
3. integrate with libsamsung-ipc @ replicant/FSO

#endif

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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

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
	SetPortConf,

	ReqSecStart,
	ReqSecEnd,
	ReqForceHwReset,

	ReqFlashSetAddress,
	ReqFlashWriteBlock,
};

struct {
	unsigned code;
	size_t data_size;
	bool need_ack;
} xmm6260_boot_cmd_desc[] = {
	[SetPortConf] = {
		.code = 0x86,
		.data_size = 0x800,
		.need_ack = 1,
	},
	[ReqSecStart] = {
		.code = 0x204,
		.data_size = 0x4000,
		.need_ack = 1,
	},
	[ReqSecEnd] = {
		.code = 0x205,
		.data_size = 0x4000,
		.need_ack = 1,
	},
	[ReqForceHwReset] = {
		.code = 0x208,
		.data_size = 0x4000,
		.need_ack = 0,
	},
	[ReqFlashSetAddress] = {
		.code = 0x802,
		.data_size = 0x4000,
		.need_ack = 1,
	},
	[ReqFlashWriteBlock] = {
		.code = 0x804,
		.data_size = 0x4000,
		.need_ack = 0,
	},
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
	
	if (type >= ARRAY_SIZE(i9100_radio_parts)) {
		_e("bad image type %x", type);
		goto fail;
	}

	size_t length = i9100_radio_parts[type].length;
	size_t offset = i9100_radio_parts[type].offset;

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
	unsigned length = i9100_radio_parts[EBL].length;

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

static int bootloader_cmd(fwloader_context *ctx, enum xmm6260_boot_cmd cmd,
	void *data, size_t data_size)
{
	int ret = 0;
	if (cmd >= ARRAY_SIZE(xmm6260_boot_cmd_desc)) {
		_e("bad command %x\n", cmd);
		goto done_or_fail;
	}

	unsigned cmd_code = xmm6260_boot_cmd_desc[cmd].code;

	uint16_t magic = (data_size & 0xffff) + cmd_code;
	unsigned char *ptr = (unsigned char*)data;
	for (size_t i = 0; i < data_size; i++) {
		magic += ptr[i];
	}

	bootloader_cmd_t header = {
		.check = magic,
		.cmd = cmd_code,
		.data_size = data_size,
	};

	size_t cmd_size = xmm6260_boot_cmd_desc[cmd].data_size;
	size_t buf_size = cmd_size + sizeof(header);

	char *cmd_data = (char*)malloc(buf_size);
	if (!cmd_data) {
		_e("failed to allocate command buffer");
		ret = -ENOMEM;
		goto done_or_fail;
	}
	memset(cmd_data, 0, buf_size);
	memcpy(cmd_data, &header, sizeof(header));
	memcpy(cmd_data + sizeof(header), data, data_size);

	if ((ret = write(ctx->boot_fd, cmd_data, buf_size)) < 0) {
		_e("failed to write command to socket");
		goto done_or_fail;
	}

	if (ret != buf_size) {
		_e("written %d bytes of %d", ret, buf_size);
		ret = -EINVAL;
		goto done_or_fail;
	}

	_d("sent command %x magic=%x", header.cmd, header.check);

	if (!xmm6260_boot_cmd_desc[cmd].need_ack) {
		ret = 0;
		goto done_or_fail;
	}

	bootloader_cmd_t ack = {};
	if ((ret = receive(ctx->boot_fd, &ack, sizeof(ack))) < 0) {
		_e("failed to receive ack for cmd %x", header.cmd);
		goto done_or_fail;
	}

	if (ret != sizeof(ack)) {
		_e("received %x bytes of %x for ack", ret, sizeof(ack));
		ret = -EINVAL;
		goto done_or_fail;
	}

	hexdump(&ack, sizeof(ack));

	if (ack.cmd != header.cmd) {
		_e("ack cmd %x does not match request %x", ack.cmd, header.cmd);
		ret = -EINVAL;
		goto done_or_fail;
	}

	if ((ret = receive(ctx->boot_fd, data, data_size)) < 0) {
		_e("failed to receive reply data");
		goto done_or_fail;
	}

	if (ret != data_size) {
		_e("received %x bytes of %x for reply data", ret, data_size);
		ret = -EINVAL;
		goto done_or_fail;
	}


done_or_fail:

	if (cmd_data) {
		free(cmd_data);
	}

	return ret;
}

static int ack_BootInfo(fwloader_context *ctx) {
	int ret;
	boot_info_t info;
	
	if ((ret = receive(ctx->boot_fd, &info, sizeof(info))) != sizeof(info)) {
		_e("failed to receive Boot Info ret=%d", ret);
		ret = -1;
		goto fail;
	}
	else {
		_d("received Boot Info");
		hexdump(&info, sizeof(info));
	}

	if ((ret = bootloader_cmd(ctx, SetPortConf, &info, sizeof(info))) < 0) {
		_e("failed to send SetPortConf command");
		goto fail;
	}
	else {
		_d("sent SetPortConf command");
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

	if ((ret = ack_BootInfo(&ctx)) < 0) {
		_e("failed to receive Boot Info");
		goto fail;
	}
	else {
		_d("Boot Info ACK done");
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

	_i("online");

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
