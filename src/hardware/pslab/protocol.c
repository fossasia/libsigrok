/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2020 Daniel Maslowski <info@orangecms.org>
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

#include <config.h>
#include <string.h>
#include "protocol.h"

// static const uint8_t CMD_GET_VERSION[] = { 0xb, 0x5 };

static const uint8_t PSL_VERSION_PACKET_LEN = 2;

static const uint8_t MAX_REPLY_SIZE = 20;

SR_PRIV int pslab_get_version(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_usb_dev_inst *conn;
	int len, ret;
	unsigned char buf[MAX_REPLY_SIZE];

	uint8_t *cmd_buf, *resp_buf, checksum;

	sr_info("Asking for version.");

	devc = sdi->priv;
	conn = sdi->conn;

	if (!devc || !conn)
		return SR_ERR_NA;

	cmd_buf = g_malloc0(sizeof(CMD_GET_VERSION));
	memcpy(&cmd_buf[0], CMD_GET_VERSION, 2);

	resp_buf = g_malloc0(MAX_REPLY_SIZE);
	if (!cmd_buf || !resp_buf)
		return SR_ERR_MALLOC;

	sr_dbg("Probing serial port: %s", conn);

  ret = serial_write_blocking(conn, cmd_buf, PSL_VERSION_PACKET_LEN,
        serial_timeout(conn, PSL_VERSION_PACKET_LEN));

	if (ret < 3) {
		sr_dbg("%s: Error sending command 0x%02x: %d", __func__,
			PSL_VERSION_PACKET_LEN, ret);
		ret = SR_ERR;
  }
	len = serial_read_blocking(conn, resp_buf, MAX_REPLY_SIZE, 100);

	serial_close(conn);
	sr_serial_dev_inst_free(conn);
	conn = NULL;

	sr_info("  Got version: %s", resp_buf);

	g_free(cmd_buf);
	g_free(resp_buf);

	return SR_OK;
}

SR_PRIV int pslab_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents == G_IO_IN) {
		/* TODO */
	}

	return TRUE;
}
