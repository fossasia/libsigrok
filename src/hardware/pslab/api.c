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

/**
 * For the basic PSLab command protocol, see
 * https://github.com/fossasia/pslab-firmware/blob/master/docs/CommunicationProtocol.md
 */

#include <config.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "protocol.h"

#define SERIALCOMM "115200/8n1"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
	SR_CONF_SERIALCOMM,
};

static const uint32_t drvopts[] = {
	SR_CONF_MULTIMETER,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_SET,
	SR_CONF_LIMIT_MSEC | SR_CONF_SET,
};

static const uint8_t GET_VERSION[] = { 0xb, 0x5 };

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct dev_context *devc;
	struct sr_serial_dev_inst *serial;
	struct sr_dev_inst *sdi;
	GSList *devices, *l;
	const char *conn = NULL, *serialcomm = NULL, *pslab_version;
	uint8_t buf[42]; // TODO: What is reasonable? telefino uses 292
	size_t len;
	struct sr_config *src;

	devices = NULL;
	len = sizeof(buf);

  // based on teleinfo
	for (l = options; l; l = l->next) {
		src = l->data;
		switch (src->key) {
		case SR_CONF_CONN:
			conn = g_variant_get_string(src->data, NULL);
			break;
		case SR_CONF_SERIALCOMM:
			serialcomm = g_variant_get_string(src->data, NULL);
			break;
	}
	if (!conn)
		return NULL;
	if (!serialcomm)
		serialcomm = SERIALCOMM;

	serial = sr_serial_dev_inst_new(conn, serialcomm);

	if (serial_open(serial, SERIAL_RDONLY) != SR_OK)
		return NULL;

	sr_info("Probing serial port %s.", conn);

  // TODO
	/* Try reading PSLab board version */
  pslab_version = pslab_get_version(sdi);
	if (!pslab_version)
		goto scan_cleanup;

	sr_info("Found device on port %s.", conn);

	sdi = g_malloc0(sizeof(struct sr_dev_inst));
	sdi->status = SR_ST_INACTIVE;
	sdi->vendor = g_strdup("FOSSASIA");
	sdi->model = g_strdup("PSLab v6"); // TODO: use detected version
	devc = g_malloc(sizeof(struct dev_context));
  sdi->inst_type = SR_INST_SERIAL;
  sdi->conn = serial;
	sdi->priv = devc;


	devices = g_slist_append(devices, sdi);

scan_cleanup:
	serial_close(serial);

	return std_scan_complete(di, devices);
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	(void)sdi;

	return SR_OK;
}

static struct sr_dev_driver pslab_driver_info = {
	.name = "pslab",
	.longname = "PSLab",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get, // or just NULL
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = std_serial_dev_open,
	.dev_close = std_serial_dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = std_serial_dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(pslab_driver_info);
