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

#ifndef __MODEMCTL_COMMON_H__
#define __MODEMCTL_COMMON_H__

#include "common.h"
#include "log.h"
#include "io_helpers.h" 

//Samsung IOCTLs
#include "modem_prj.h"

#define MODEM_DEVICE(x) ("/dev/" #x)
#define LINK_PM MODEM_DEVICE(link_pm)
#define MODEM_DEV MODEM_DEVICE(modem_br)
#define BOOT_DEV MODEM_DEVICE(umts_boot0)
#define IPC_DEV MODEM_DEVICE(umts_ipc0)
#define RFS_DEV MODEM_DEVICE(umts_rfs0)

#define LINK_POLL_DELAY_US (50 * 1000)
#define LINK_TIMEOUT_MS 2000

#define RADIO_MAP_SIZE (16 << 20)

typedef struct {
	int link_fd;
	int boot_fd;

	int radio_fd;
	char *radio_data;
	struct stat radio_stat;
} fwloader_context;

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

/*
 * Function prototypes
 */

/* 
 * @brief Activates the modem <-> cpu link data transfer
 *
 * @param ctx [in] firmware loader context
 * @param enabled [in] whether to enable or disable link data transport
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int modemctl_link_set_active(fwloader_context *ctx, bool enabled);

/* 
 * @brief Activates the modem <-> cpu link connection
 *
 * @param ctx [in] firmware loader context
 * @param enabled [in] the state to set link to
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int modemctl_link_set_enabled(fwloader_context *ctx, bool enabled);

/* 
 * @brief Poll the link until it gets ready or times out
 *
 * @param ctx [in] firmware loader context
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int modemctl_wait_link_ready(fwloader_context *ctx);

/* 
 * @brief Sets the modem power
 *
 * @param ctx [in] firmware loader context
 * @param enabled [in] whether to enable or disable modem power
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int modemctl_modem_power(fwloader_context *ctx, bool enabled);

/* 
 * @brief Sets the modem bootloader power/UART configuration
 *
 * @param ctx [in] firmware loader context
 * @param enabled [in] whether to enable or disable power
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int modemctl_modem_boot_power(fwloader_context *ctx, bool enabled);

/* 
 * @brief Boots the modem on the I9100 (Galaxy S2) board
 *
 * @return Negative value indicating error code
 * @return zero on success
 */
int boot_modem_i9100(void);

/* 
 * @brief Boots the modem on the I9250 (Galaxy Nexus) board
 *
 * @return Negative value indicating error code
 * @return zero on success
 */
int boot_modem_i9250(void);

#endif //__MODEMCTL_COMMON_H__
