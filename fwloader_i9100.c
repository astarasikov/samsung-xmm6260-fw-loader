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

/*
 * I9100 specific implementation
 */
#define RADIO_IMAGE "/dev/block/mmcblk0p8"
#define NVDATA_IMAGE "/efs/nv_data.bin"
#define I9100_EHCI_PATH "/sys/devices/platform/s5p-ehci/ehci_power"

#define LINK_POLL_DELAY_US (50 * 1000)
#define LINK_TIMEOUT_MS 2000

#define XMM_PSI_MAGIC 0x30
#define PSI_ACK_MAGIC "\x00\xaa"

#define EBL_HDR_ACK_MAGIC "\xcc\xcc"
#define EBL_IMG_ACK_MAGIC "\x51\xa5"

#define BL_END_MAGIC "\x00\x00"
#define BL_END_MAGIC_LEN 2

#define BL_RESET_MAGIC "\x01\x10\x11\x00" 
#define BL_RESET_MAGIC_LEN 4

#define SEC_DOWNLOAD_CHUNK 16384
#define SEC_DOWNLOAD_DELAY_US (500 * 1000)

#define POST_BOOT_TIMEOUT_US (600 * 1000)

#define FW_LOAD_ADDR 0x60300000
#define NVDATA_LOAD_ADDR 0x60e80000

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
		.offset = 0xa00000,
		.length = 2 << 20,
	}
};

struct {
	unsigned code;
	size_t data_size;
	bool need_ack;
} i9100_boot_cmd_desc[] = {
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
		ret = write(ctx->boot_fd, ctx->radio_data + start, end - start);
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
	else {
		_d("wrote CRC %x", crc);
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

	int i;
	for (i = 0; i < 22; i++) {
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
	
	if ((ret = expect_data(ctx->boot_fd, PSI_ACK_MAGIC, 2)) < 0) {
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

	if ((ret = expect_data(fd, EBL_HDR_ACK_MAGIC, 2)) < 0) {
		_e("failed to wait for EBL header ACK");
		goto fail;
	}
	
	if ((ret = send_image(ctx, EBL)) < 0) {
		_e("failed to send EBL image");
		goto fail;
	}
	
	if ((ret = expect_data(fd, EBL_IMG_ACK_MAGIC, 2)) < 0) {
		_e("failed to wait for EBL image ACK");
		goto fail;
	}

	return 0;

fail:
	return ret;
}

static int bootloader_cmd(fwloader_context *ctx, enum xmm6260_boot_cmd cmd,
	void *data, size_t data_size)
{
	int ret = 0;
	if (cmd >= ARRAY_SIZE(i9100_boot_cmd_desc)) {
		_e("bad command %x\n", cmd);
		goto done_or_fail;
	}

	unsigned cmd_code = i9100_boot_cmd_desc[cmd].code;

	uint16_t magic = (data_size & 0xffff) + cmd_code;
	unsigned char *ptr = (unsigned char*)data;
	size_t i;
	for (i = 0; i < data_size; i++) {
		magic += ptr[i];
	}

	bootloader_cmd_t header = {
		.check = magic,
		.cmd = cmd_code,
		.data_size = data_size,
	};

	size_t cmd_size = i9100_boot_cmd_desc[cmd].data_size;
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

	_d("bootloader cmd packet");
	hexdump(cmd_data, buf_size);

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

	if (!i9100_boot_cmd_desc[cmd].need_ack) {
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

	if ((ret = receive(ctx->boot_fd, cmd_data, cmd_size)) < 0) {
		_e("failed to receive reply data");
		goto done_or_fail;
	}

	if (ret != cmd_size) {
		_e("received %x bytes of %x for reply data", ret, cmd_size);
		ret = -EINVAL;
		goto done_or_fail;
	}
	hexdump(cmd_data, cmd_size);

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

static int send_image_addr(fwloader_context *ctx, uint32_t addr,
	enum xmm6260_image type)
{
	int ret = 0;
	if ((ret = bootloader_cmd(ctx, ReqFlashSetAddress, &addr, 4)) < 0) {
		_e("failed to send ReqFlashSetAddress");
		goto fail;
	}
	else {
		_d("sent ReqFlashSetAddress");
	}

	uint32_t offset = i9100_radio_parts[type].offset;
	uint32_t length = i9100_radio_parts[type].length;

	char *start = ctx->radio_data + offset;
	char *end = start + length;

	while (start < end) {
		unsigned rest = end - start;
		unsigned chunk = rest < SEC_DOWNLOAD_CHUNK ? rest : SEC_DOWNLOAD_CHUNK;

		ret = bootloader_cmd(ctx, ReqFlashWriteBlock, start, chunk);
		if (ret < 0) {
			_e("failed to send data chunk");
			goto fail;
		}

		start += chunk;
	}

	usleep(SEC_DOWNLOAD_DELAY_US);

fail:
	return ret;
}

static int send_SecureImage(fwloader_context *ctx) {
	int ret = 0;

	uint32_t sec_off = i9100_radio_parts[SECURE_IMAGE].offset;
	uint32_t sec_len = i9100_radio_parts[SECURE_IMAGE].length;
	void *sec_img = ctx->radio_data + sec_off;
	
	if ((ret = bootloader_cmd(ctx, ReqSecStart, sec_img, sec_len)) < 0) {
		_e("failed to write ReqSecStart");
		goto fail;
	}
	else {
		_d("sent ReqSecStart");
	}

	if ((ret = send_image_addr(ctx, FW_LOAD_ADDR, FIRMWARE)) < 0) {
		_e("failed to send FIRMWARE image");
		goto fail;
	}
	else {
		_d("sent FIRMWARE image");
	}
	
	if ((ret = send_image_addr(ctx, NVDATA_LOAD_ADDR, NVDATA)) < 0) {
		_e("failed to send NVDATA image");
		goto fail;
	}
	else {
		_d("sent NVDATA image");
	}

	if ((ret = bootloader_cmd(ctx, ReqSecEnd,
		BL_END_MAGIC, BL_END_MAGIC_LEN)) < 0)
	{
		_e("failed to write ReqSecEnd");
		goto fail;
	}
	else {
		_d("sent ReqSecEnd");
	}

	ret = bootloader_cmd(ctx, ReqForceHwReset,
		BL_RESET_MAGIC, BL_RESET_MAGIC_LEN);
	if (ret < 0) {
		_e("failed to write ReqForceHwReset");
		goto fail;
	}
	else {
		_d("sent ReqForceHwReset");
	}

fail:
	return ret;
}

/*
 * i9200 (Galaxy S2) board-specific code
 */

/*
 * Power management
 */
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

static int reboot_modem_i9100(fwloader_context *ctx, bool hard) {
	int ret;
	
	//wait for link to become ready before redetection
	if (!hard) {
		if ((ret = modemctl_wait_link_ready(ctx)) < 0) {
			_e("failed to wait for link to get ready for redetection");
			goto fail;
		}
		else {
			_d("link ready for redetection");
		}
	}

	/*
	 * Disable the hardware to ensure consistent state
	 */
	if (hard) {	
		if ((ret = modemctl_modem_power(ctx, false)) < 0) {
			_e("failed to disable xmm6260 power");
			goto fail;
		}
		else {
			_d("disabled xmm6260 power");
		}
	}
	
	if ((ret = modemctl_link_set_enabled(ctx, false)) < 0) {
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
	
	if ((ret = modemctl_link_set_active(ctx, false)) < 0) {
		_e("failed to deactivate I9100 HSIC link");
		goto fail;
	}
	else {
		_d("deactivated I9100 HSIC link");
	}
	
	/*
	 * Now, initialize the hardware
	 */
	
	if ((ret = modemctl_link_set_enabled(ctx, true)) < 0) {
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

	if ((ret = modemctl_link_set_active(ctx, true)) < 0) {
		_e("failed to activate I9100 HSIC link");
		goto fail;
	}
	else {
		_d("activated I9100 HSIC link");
	}
	
	if (hard) {
		if ((ret = modemctl_modem_power(ctx, true)) < 0) {
			_e("failed to enable xmm6260 power");
			goto fail;
		}
		else {
			_d("enabled xmm6260 power");
		}
	}

	if ((ret = modemctl_wait_link_ready(ctx)) < 0) {
		_e("failed to wait for link to get ready");
		goto fail;
	}
	else {
		_d("link ready");
	}
	
fail:
	return ret;
}

int boot_modem_i9100(void) {
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

	ctx.boot_fd = open(BOOT_DEV, O_RDWR | O_NOCTTY | O_NONBLOCK);
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

	if (reboot_modem_i9100(&ctx, true)) {
		_e("failed to hard reset modem");
		goto fail;
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

	if ((ret = send_SecureImage(&ctx)) < 0) {
		_e("failed to upload Secure Image");
		goto fail;
	}
	else {
		_d("Secure Image download complete");
	}

	usleep(POST_BOOT_TIMEOUT_US);

	if ((ret = reboot_modem_i9100(&ctx, false))) {
		_e("failed to soft reset modem");
		goto fail;
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

	return ret;
}

