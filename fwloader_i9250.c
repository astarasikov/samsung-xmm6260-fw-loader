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
 * i9250 (Galaxy Nexus) board-specific code
 */
#define I9250_RADIO_IMAGE "/dev/block/platform/omap/omap_hsmmc.0/by-name/radio"
#define I9250_SECOND_BOOT_DEV "/dev/umts_boot1"

#define I9250_BOOT_LAST_MARKER 0x0030ffff
#define I9250_BOOT_REPLY_MAX 20

#define I9250_GENERAL_ACK "\x02\x00\x00\x00"

#define I9250_PSI_START_MAGIC "\xff\xf0\x00\x30"
#define I9250_PSI_CMD_EXEC "\x08\x00\x00\x00"
#define I9250_PSI_EXEC_DATA "\x00\x00\x00\x00\x02\x00\x02\x00"
#define I9250_PSI_READY_ACK "\x00\xaa\x00\x00" 

#define I9250_EBL_IMG_ACK_MAGIC "\x51\xa5\x00\x00"
#define I9250_EBL_HDR_ACK_MAGIC "\xcc\xcc\x00\x00" 

#define I9250_MPS_IMAGE_PATH "/factory/imei/mps_code.dat"
#define I9250_MPS_LOAD_ADDR 0x61080000
#define I9250_MPS_LENGTH 3

#define SEC_DOWNLOAD_CHUNK 0xdfc2
#define SEC_DOWNLOAD_DELAY_US (500 * 1000)

	#define FW_LOAD_ADDR 0x60300000
#define NVDATA_LOAD_ADDR 0x60e80000

#define BL_END_MAGIC "\x00\x00"
#define BL_END_MAGIC_LEN 2

#define BL_RESET_MAGIC "\x01\x10\x11\x00" 
#define BL_RESET_MAGIC_LEN 4

typedef struct {
	uint32_t total_size;
	uint16_t hdr_magic;
	uint16_t cmd;
	uint16_t data_size;
} __attribute__((packed)) bootloader_cmd_hdr_t;

#define DECLARE_BOOT_CMD_HEADER(name, code, size) \
bootloader_cmd_hdr_t name = {\
	.total_size = size + 10,\
	.hdr_magic = 2,\
	.cmd = code,\
	.data_size = size,\
}

typedef struct {
	uint16_t checksum;
	uint16_t tail_magic;
	uint8_t unknown[2];
} __attribute__((packed)) bootloader_cmd_tail_t;

#define DECLARE_BOOT_TAIL_HEADER(name, checksum) \
bootloader_cmd_tail_t name = {\
	.checksum = checksum,\
	.tail_magic = 3,\
	.unknown = "\xea\xea",\
}

/*
 * Locations of the firmware components in the Samsung firmware
 */
static struct xmm6260_offset {
	size_t offset;
	size_t length;
} i9250_radio_parts[] = {
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

/*
 * on I9250, all commands need ACK and we do not need to
 * allocate a fixed size buffer
 */

struct {
	unsigned code;
	bool long_tail;
	bool no_ack;
} i9250_boot_cmd_desc[] = {
	[SetPortConf] = {
		.code = 0x86,
		.long_tail = 1,
	},
	[ReqSecStart] = {
		.code = 0x204,
		.long_tail = 1,
	},
	[ReqSecEnd] = {
		.code = 0x205,
	},
	[ReqForceHwReset] = {
		.code = 0x208,
		.long_tail = 1,
		.no_ack = 1,
	},
	[ReqFlashSetAddress] = {
		.code = 0x802,
		.long_tail = 1,
	},
	[ReqFlashWriteBlock] = {
		.code = 0x804,
	},
};

static int reboot_modem_i9250(fwloader_context *ctx, bool hard) {
	int ret;

	if (!hard) {
		return 0;
	}

	/*
	 * Disable the hardware to ensure consistent state
	 */
	if ((ret = modemctl_modem_power(ctx, false)) < 0) {
		_e("failed to disable modem power");
		goto fail;
	}
	else {
		_d("disabled modem power");
	}
	
	if ((ret = modemctl_modem_boot_power(ctx, false)) < 0) {
		_e("failed to disable modem boot power");
		goto fail;
	}
	else {
		_d("disabled modem boot power");
	}
	
	/*
	 * Now, initialize the hardware
	 */
	if ((ret = modemctl_modem_boot_power(ctx, true)) < 0) {
		_e("failed to enable modem boot power");
		goto fail;
	}
	else {
		_d("enabled modem boot power");
	}
	
	if ((ret = modemctl_modem_power(ctx, true)) < 0) {
		_e("failed to enable modem power");
		goto fail;
	}
	else {
		_d("enabled modem power");
	}

fail:
	return ret;
}

static int send_image_i9250(fwloader_context *ctx, enum xmm6260_image type) {
	int ret;
	
	if (type >= ARRAY_SIZE(i9250_radio_parts)) {
		_e("bad image type %x", type);
		goto fail;
	}

	size_t length = i9250_radio_parts[type].length;
	size_t offset = i9250_radio_parts[type].offset;

	size_t start = offset;
	size_t end = length + start;
	
	unsigned char crc = calculateCRC(ctx->radio_data, offset, length);

	//dump some image bytes
	_d("image start");
	hexdump(ctx->radio_data + start, length);

	size_t chunk_size = 0xdfc;

	while (start < end) {
		size_t remaining = end - start;
		size_t curr_chunk = chunk_size < remaining ? chunk_size : remaining;
		ret = write(ctx->boot_fd, ctx->radio_data + start, curr_chunk);
		if (ret < 0) {
			_e("failed to write image chunk");
			goto fail;
		}
		start += ret;
	}
	_d("sent image type=%d", type);

	if (type == EBL) {
		if ((ret = write(ctx->boot_fd, &crc, 1)) < 1) {
			_e("failed to write EBL CRC");
			goto fail;
		}
		else {
			_d("wrote EBL CRC %02x", crc);
		}
		goto done;
	}

	uint32_t crc32 = (crc << 24) | 0xffffff;
	if ((ret = write(ctx->boot_fd, &crc32, 4)) != 4) {
		_e("failed to write CRC");
		goto fail;
	}
	else {
		_d("wrote CRC %x", crc);
	}

done:
	ret = 0;

fail:
	return ret;
}

static int send_PSI_i9250(fwloader_context *ctx) {
	int ret = -1;

	if ((ret = write(ctx->boot_fd, I9250_PSI_START_MAGIC, 4)) < 0) {
		_d("%s: failed to write header, ret %d", __func__, ret);
		goto fail;
	}

	if ((ret = send_image_i9250(ctx, PSI)) < 0) {
		_e("failed to send PSI image");
		goto fail;
	}

	char expected_acks[4][4] = {
		"\xff\xff\xff\x01",
		"\xff\xff\xff\x01",
		"\x02\x00\x00\x00",
		"\x01\xdd\x00\x00",
	};
	
	int i;
	for (i = 0; i < ARRAY_SIZE(expected_acks); i++) {
		ret = expect_data(ctx->boot_fd, expected_acks[i], 4);
		if (ret < 0) {
			_d("failed to wait for ack %d", i);
			goto fail;
		}
	}
	_d("received PSI ACK");

	return 0;

fail:
	return ret;
}

static int send_EBL_i9250(fwloader_context *ctx) {
	int ret;
	int fd = ctx->boot_fd;
	unsigned length = i9250_radio_parts[EBL].length;
	
	if ((ret = write(fd, "\x04\x00\x00\x00", 4)) != 4) {
		_e("failed to write length of EBL length ('4') ");
		goto fail;
	}

	if ((ret = write(fd, &length, sizeof(length))) != sizeof(length)) {
		_e("failed to write EBL length");
		goto fail;
	}

	if ((ret = expect_data(fd, I9250_GENERAL_ACK, 4)) < 0) {
		_e("failed to wait for EBL length ACK");
		goto fail;
	}

	if ((ret = expect_data(fd, I9250_EBL_HDR_ACK_MAGIC, 4)) < 0) {
		_e("failed to wait for EBL header ACK");
		goto fail;
	}
	
	length++;
	if ((ret = write(fd, &length, sizeof(length))) != sizeof(length)) {
		_e("failed to write EBL length + 1");
		goto fail;
	}
	
	if ((ret = send_image_i9250(ctx, EBL)) < 0) {
		_e("failed to send EBL image");
		goto fail;
	}
	else {
		_d("sent EBL image, waiting for ACK");
	}

	if ((ret = expect_data(fd, I9250_GENERAL_ACK, 4)) < 0) {
		_e("failed to wait for EBL image general ACK");
		goto fail;
	}

	if ((ret = expect_data(fd, I9250_EBL_IMG_ACK_MAGIC, 4)) < 0) {
		_e("failed to wait for EBL image ACK");
		goto fail;
	}
	else {
		_d("got EBL ACK");
	}

	return 0;

fail:
	return ret;
}

static int bootloader_cmd(fwloader_context *ctx,
	enum xmm6260_boot_cmd cmd, void *data, size_t data_size)
{
	int ret = 0;
	if (cmd >= ARRAY_SIZE(i9250_boot_cmd_desc)) {
		_e("bad command %x\n", cmd);
		goto done_or_fail;
	}

	unsigned cmd_code = i9250_boot_cmd_desc[cmd].code;

	uint16_t checksum = (data_size & 0xffff) + cmd_code;
	unsigned char *ptr = (unsigned char*)data;
	size_t i;
	for (i = 0; i < data_size; i++) {
		checksum += ptr[i];
	}

	DECLARE_BOOT_CMD_HEADER(header, cmd_code, data_size);
	DECLARE_BOOT_TAIL_HEADER(tail, checksum);

	size_t tail_size = sizeof(tail);
	if (!i9250_boot_cmd_desc[cmd].long_tail) {
		tail_size -= 2;
	}

	size_t cmd_buffer_size = data_size + sizeof(header) + tail_size;
	_d("data_size %d [%d] checksum 0x%x", data_size, cmd_buffer_size, checksum);

	char *cmd_data = (char*)malloc(cmd_buffer_size);
	if (!cmd_data) {
		_e("failed to allocate command buffer");
		ret = -ENOMEM;
		goto done_or_fail;
	}
	memset(cmd_data, 0, cmd_buffer_size);
	memcpy(cmd_data, &header, sizeof(header));
	memcpy(cmd_data + sizeof(header), data, data_size);
	memcpy(cmd_data + sizeof(header) + data_size, &tail, tail_size);

	_d("bootloader cmd packet");
	hexdump(cmd_data, cmd_buffer_size);
	hexdump(cmd_data + cmd_buffer_size - 16, 16);

	if ((ret = write(ctx->boot_fd, cmd_data, cmd_buffer_size)) < 0) {
		_e("failed to write command to socket");
		goto done_or_fail;
	}

	if (ret < cmd_buffer_size) {
		_e("written %d bytes of %d", ret, cmd_buffer_size);
		ret = -EINVAL;
		goto done_or_fail;
	}

	_d("sent command %x", header.cmd);
	if (i9250_boot_cmd_desc[cmd].no_ack) {
		_i("not waiting for ACK");
		goto done_or_fail;
	}

	uint32_t ack_length;
	if ((ret = receive(ctx->boot_fd, &ack_length, 4)) < 0) {
		_e("failed to receive ack header length");
		goto done_or_fail;
	}

	if (ack_length + 4 > cmd_buffer_size) {
		free(cmd_data);
		cmd_data = NULL;
		cmd_data = malloc(ack_length + 4);
		if (!cmd_data) {
			_e("failed to allocate the buffer for ack data");
			goto done_or_fail;
		}
	}
	memset(cmd_data, 0, ack_length);
	memcpy(cmd_data, &ack_length, 4);
	for (i = 0; i < (ack_length + 3) / 4; i++) {
		if ((ret = receive(ctx->boot_fd, cmd_data + ((i + 1) << 2), 4)) < 0) {
			_e("failed to receive ack chunk");
			goto done_or_fail;
		}
	}

	_d("received ack");
	hexdump(cmd_data, ack_length + 4);

	bootloader_cmd_hdr_t *ack_hdr = (bootloader_cmd_hdr_t*)cmd_data;
	bootloader_cmd_tail_t *ack_tail = (bootloader_cmd_tail_t*)
		(cmd_data + ack_length + 4 - sizeof(bootloader_cmd_tail_t));
	
	_d("ack code 0x%x checksum 0x%x", ack_hdr->cmd, ack_tail->checksum);
	if (ack_hdr->cmd != header.cmd) {
		_e("request and ack command codes do not match");
		ret = -1;
		goto done_or_fail;
	}

	ret = 0;

done_or_fail:

	if (cmd_data) {
		free(cmd_data);
	}

	return ret;
}

static int ack_BootInfo_i9250(fwloader_context *ctx) {
	int ret = -1;
	uint32_t boot_info_length;
	char *boot_info = 0;


	if ((ret = receive(ctx->boot_fd, &boot_info_length, 4)) < 0) {
		_e("failed to receive boot info length");
		goto fail;
	}

	_d("Boot Info length=0x%x", boot_info_length);

	boot_info = (char*)malloc(boot_info_length);
	if (!boot_info) {
		_e("failed to allocate memory for boot info");
		goto fail;
	}
	
	memset(boot_info, 0, boot_info_length);

	size_t boot_chunk = 4;
	size_t boot_chunk_count = (boot_info_length + boot_chunk - 1) / boot_chunk;
	int i;
	for (i = 0; i < boot_chunk_count; i++) {
		ret = receive(ctx->boot_fd, boot_info + (i * boot_chunk), boot_chunk);
		if (ret < 0) {
			_e("failed to receive Boot Info chunk %i ret=%d", i, ret);
			goto fail;
		}
	}
	
	_d("received Boot Info");
	hexdump(boot_info, boot_info_length);

	ret = bootloader_cmd(ctx, SetPortConf, boot_info, boot_info_length);
	if (ret < 0) {
		_e("failed to send SetPortConf command");
		goto fail;
	}
	else {
		_d("sent SetPortConf command");
	}

	ret = 0;

fail:
	if (boot_info) {
		free(boot_info);
	}

	return ret;
}

static int send_secure_image(fwloader_context *ctx, uint32_t addr,
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

	uint32_t offset = i9250_radio_parts[type].offset;
	uint32_t length = i9250_radio_parts[type].length;

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

static int send_mps_data(fwloader_context *ctx) {
	int ret = 0;
	int mps_fd = -1;
	char mps_data[I9250_MPS_LENGTH] = {};
	uint32_t addr = I9250_MPS_LOAD_ADDR;

	mps_fd = open(I9250_MPS_IMAGE_PATH, O_RDONLY);
	if (mps_fd < 0) {
		_e("failed to open MPS data");
	}
	else {
		read(mps_fd, mps_data, I9250_MPS_LENGTH);
	}
	
	if ((ret = bootloader_cmd(ctx, ReqFlashSetAddress, &addr, 4)) < 0) {
		_e("failed to send ReqFlashSetAddress");
		goto fail;
	}
	else {
		_d("sent ReqFlashSetAddress");
	}

	if ((ret = bootloader_cmd(ctx, ReqFlashWriteBlock,
		mps_data, I9250_MPS_LENGTH)) < 0) {
		_e("failed to write MPS data to modem");
		goto fail;
	}


fail:
	if (mps_fd >= 0) {
		close(mps_fd);
	}

	return ret;
}

static int send_SecureImage_i9250(fwloader_context *ctx) {
	int ret = 0;

	uint32_t sec_off = i9250_radio_parts[SECURE_IMAGE].offset;
	uint32_t sec_len = i9250_radio_parts[SECURE_IMAGE].length;
	void *sec_img = ctx->radio_data + sec_off;
	
	if ((ret = bootloader_cmd(ctx, ReqSecStart, sec_img, sec_len)) < 0) {
		_e("failed to write ReqSecStart");
		goto fail;
	}
	else {
		_d("sent ReqSecStart");
	}

	if ((ret = send_secure_image(ctx, FW_LOAD_ADDR, FIRMWARE)) < 0) {
		_e("failed to send FIRMWARE image");
		goto fail;
	}
	else {
		_d("sent FIRMWARE image");
	}
	
	if ((ret = send_secure_image(ctx, NVDATA_LOAD_ADDR, NVDATA)) < 0) {
		_e("failed to send NVDATA image");
		goto fail;
	}
	else {
		_d("sent NVDATA image");
	}

	if ((ret = send_mps_data(ctx)) < 0) {
		_e("failed to send MPS data");
		goto fail;
	}
	else {
		_d("sent MPS data");
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

int boot_modem_i9250(void) {
	int ret;
	fwloader_context ctx;
	memset(&ctx, 0, sizeof(ctx));

	ctx.radio_fd = open(I9250_RADIO_IMAGE, O_RDONLY);
	if (ctx.radio_fd < 0) {
		_e("failed to open radio firmware");
		goto fail;
	}
	else {
		_d("opened radio image %s, fd=%d", I9250_RADIO_IMAGE, ctx.radio_fd);
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

	if (reboot_modem_i9250(&ctx, true) < 0) {
		_e("failed to hard reset modem");
		goto fail;
	}
	else {
		_d("modem hard reset done");
	}

	/*
	 * Now, actually load the firmware
	 */
	int i;
	for (i = 0; i < 2; i++) {
		if (write(ctx.boot_fd, "ATAT", 4) != 4) {
			_e("failed to write ATAT to boot socket");
			goto fail;
		}
		else {
			_d("written ATAT to boot socket, waiting for ACK");
		}
		
		if (read_select(ctx.boot_fd, 100) < 0) {
			_d("failed to select before next ACK, ignoring");
		}
	}

	//FIXME: make sure it does not timeout or add the retry in the ril library
	
	if ((ret = read_select(ctx.boot_fd, 100)) < 0) {
		_e("failed to wait for bootloader ready state");
		goto fail;
	}
	else {
		_d("ready for PSI upload");
	}

	ret = -ETIMEDOUT;
	for (i = 0; i < I9250_BOOT_REPLY_MAX; i++) {
		uint32_t id_buf;
		if ((ret = receive(ctx.boot_fd, (void*)&id_buf, 4)) != 4) {
			_e("failed receiving bootloader reply");
			goto fail;
		}
		_d("got bootloader reply %08x", id_buf);
		if (id_buf == I9250_BOOT_LAST_MARKER) {
			ret = 0;
			break;
		}
	}

	if (ret < 0) {
		_e("bootloader id marker not received");
		goto fail;
	}
	else {
		_d("got bootloader id marker");
	}

	if ((ret = send_PSI_i9250(&ctx)) < 0) {
		_e("failed to upload PSI");
		goto fail;
	}
	else {
		_d("PSI download complete");
	}
	
	close(ctx.boot_fd);
	ctx.boot_fd = open(I9250_SECOND_BOOT_DEV, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (ctx.boot_fd < 0) {
		_e("failed to open " I9250_SECOND_BOOT_DEV " control device");
		goto fail;
	}
	else {
		_d("opened second boot device %s, fd=%d", I9250_SECOND_BOOT_DEV, ctx.boot_fd);
	}

	//RpsiCmdLoadAndExecute
	if ((ret = write(ctx.boot_fd, I9250_PSI_CMD_EXEC, 4)) < 0) {
		_e("failed writing cmd_load_exe_EBL");
		goto fail;
	}
	if ((ret = write(ctx.boot_fd, I9250_PSI_EXEC_DATA, 8)) < 0) {
		_e("failed writing 8 bytes to boot1");
		goto fail;
	}

	if ((ret = expect_data(ctx.boot_fd, I9250_GENERAL_ACK, 4)) < 0) {
		_e("failed to receive cmd_load_exe_EBL ack");
		goto fail;
	}

	if ((ret = expect_data(ctx.boot_fd, I9250_PSI_READY_ACK, 4)) < 0) {
		_e("failed to receive PSI ready ack");
		goto fail;
	}

	if ((ret = send_EBL_i9250(&ctx)) < 0) {
		_e("failed to upload EBL");
		goto fail;
	}
	else {
		_d("EBL download complete");
	}

	if ((ret = ack_BootInfo_i9250(&ctx)) < 0) {
		_e("failed to receive Boot Info");
		goto fail;
	}
	else {
		_d("Boot Info ACK done");
	}

	if ((ret = send_SecureImage_i9250(&ctx)) < 0) {
		_e("failed to upload Secure Image");
		goto fail;
	}
	else {
		_d("Secure Image download complete");
	}

	if ((ret = modemctl_wait_modem_online(&ctx))) {
		_e("failed to wait for modem to become online");
		goto fail;
	}

	_i("modem online");

fail:
	if (ctx.radio_data != MAP_FAILED) {
		munmap(ctx.radio_data, RADIO_MAP_SIZE);
	}

	if (ctx.radio_fd >= 0) {
		close(ctx.radio_fd);
	}

	if (ctx.boot_fd >= 0) {
		close(ctx.boot_fd);
	}

	return ret;
}
