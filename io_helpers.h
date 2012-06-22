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

#ifndef __IO_HELPERS_H__
#define __IO_HELPERS_H__

#include "common.h"

/* 
 * @brief A wrapper around ioctl that prints the error to the log
 *
 * @param fd [in] File descriptor of the socket
 * @param code [in] ioctl code
 * @param data argument to the ioctl
 * @return Negative value indicating error code
 * @return ioctl call result
 */
int c_ioctl(int fd, unsigned long code, void* data);

/* 
 * @brief Waits for fd to become available for reading
 *
 * @param fd [in] File descriptor of the socket
 * @param timeout [in] Timeout in milliseconds
 * @return Negative value indicating error code
 * @return Available socket number - 1, as select()
 */
int read_select(int fd, unsigned timeout);

/* 
 * @brief Waits for data available and reads it to the buffer
 *
 * @param fd [in] File descriptor of the socket
 * @param buf Buffer to hold data
 * @param size [in] The number of bytes to read
 * @return Negative value indicating error code
 * @return The size of data received
 */
int receive(int fd, void *buf, size_t size);

/* 
 * @brief Receives data and compares with the pattern in memory
 *
 * @param fd [in] File descriptor of the socket
 * @param data [in] The pattern to compare to
 * @param size [in] The length of data to read in bytes
 * @return Negative value indicating error code
 * @return Available socket number - 1, as select()
 */
int expect_data(int fd, void *data, size_t size);

#endif //__IO_HELPERS_H__
