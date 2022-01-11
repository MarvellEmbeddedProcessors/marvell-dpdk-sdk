/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_telemetry.h>

#include <roc_api.h>

#include "cnxk_ethdev.h"

#define OUTB_SA_SZ sizeof(struct roc_onf_ipsec_outb_sa)
#define INB_SA_SZ  sizeof(struct roc_onf_ipsec_inb_sa)

#define STR_MAXLEN 20
#define W0_MAXLEN 21

static int
copy_outb_sa(struct rte_tel_data *d, uint32_t i, void *sa)
{
	struct roc_onf_ipsec_outb_sa *out_sa;
	struct rte_tel_data *ciph_key;
	struct rte_tel_data *hmac_key;
	union {
		struct roc_ie_onf_sa_ctl ctl;
		uint64_t u64;
	} w0;
	char strw0[W0_MAXLEN];
	char str[STR_MAXLEN];
	uint32_t nonce;
	uint32_t j;

	out_sa = (struct roc_onf_ipsec_outb_sa *)sa;
	w0.ctl = out_sa->ctl;

	nonce = *(uint32_t *)(out_sa->nonce);

	snprintf(str, sizeof(str), "outsa_w0_%u", i);
	snprintf(strw0, sizeof(strw0), "%" PRIu64, w0.u64);
	rte_tel_data_add_dict_string(d, str, strw0);

	snprintf(str, sizeof(str), "outsa_nonce_%u", i);
	rte_tel_data_add_dict_u64(d, str, nonce);

	snprintf(str, sizeof(str), "outsa_src_%u", i);
	rte_tel_data_add_dict_u64(d, str, out_sa->udp_src);

	snprintf(str, sizeof(str), "outsa_dst_%u", i);
	rte_tel_data_add_dict_u64(d, str, out_sa->udp_dst);

	snprintf(str, sizeof(str), "outsa_isrc_%u", i);
	rte_tel_data_add_dict_u64(d, str, out_sa->ip_src);

	snprintf(str, sizeof(str), "outsa_idst_%u", i);
	rte_tel_data_add_dict_u64(d, str, out_sa->ip_dst);

	ciph_key = rte_tel_data_alloc();
	if (!ciph_key) {
		plt_err("Could not allocate space for cipher key");
		return -ENOMEM;
	}

	rte_tel_data_start_array(ciph_key, RTE_TEL_U64_VAL);
	for (j = 0; j < RTE_DIM(out_sa->cipher_key); j++)
		rte_tel_data_add_array_u64(ciph_key, out_sa->cipher_key[j]);

	snprintf(str, sizeof(str), "outsa_ckey_%u", i);
	rte_tel_data_add_dict_container(d, str, ciph_key, 0);

	hmac_key = rte_tel_data_alloc();
	if (!hmac_key) {
		plt_err("Could not allocate space for hmac key");
		return -ENOMEM;
	}

	rte_tel_data_start_array(hmac_key, RTE_TEL_U64_VAL);
	for (j = 0; j < RTE_DIM(out_sa->hmac_key); j++)
		rte_tel_data_add_array_u64(hmac_key, out_sa->hmac_key[j]);

	snprintf(str, sizeof(str), "outsa_hkey_%u", i);
	rte_tel_data_add_dict_container(d, str, hmac_key, 0);

	return 0;
}

static int
copy_inb_sa(struct rte_tel_data *d, uint32_t i, void *sa)
{
	struct roc_onf_ipsec_inb_sa *in_sa;
	struct rte_tel_data *ciph_key;
	struct rte_tel_data *hmac_key;
	union {
		struct roc_ie_onf_sa_ctl ctl;
		uint64_t u64;
	} w0;
	char strw0[W0_MAXLEN];
	char str[STR_MAXLEN];
	uint32_t nonce;
	uint32_t j;

	in_sa = (struct roc_onf_ipsec_inb_sa *)sa;
	w0.ctl = in_sa->ctl;

	nonce = *(uint32_t *)(in_sa->nonce);

	snprintf(str, sizeof(str), "insa_w0_%u", i);
	snprintf(strw0, sizeof(strw0), "%" PRIu64, w0.u64);
	rte_tel_data_add_dict_string(d, str, strw0);

	snprintf(str, sizeof(str), "insa_nonce_%u", i);
	rte_tel_data_add_dict_u64(d, str, nonce);

	snprintf(str, sizeof(str), "insa_unused_%u", i);
	rte_tel_data_add_dict_u64(d, str, in_sa->unused);

	snprintf(str, sizeof(str), "insa_esnh_%u", i);
	rte_tel_data_add_dict_u64(d, str, in_sa->esn_hi);

	snprintf(str, sizeof(str), "insa_esnl_%u", i);
	rte_tel_data_add_dict_u64(d, str, in_sa->esn_low);

	ciph_key = rte_tel_data_alloc();
	if (!ciph_key) {
		plt_err("Could not allocate space for cipher key");
		return -ENOMEM;
	}

	rte_tel_data_start_array(ciph_key, RTE_TEL_U64_VAL);
	for (j = 0; j < RTE_DIM(in_sa->cipher_key); j++)
		rte_tel_data_add_array_u64(ciph_key, in_sa->cipher_key[j]);

	snprintf(str, sizeof(str), "insa_ckey_%u", i);
	rte_tel_data_add_dict_container(d, str, ciph_key, 0);

	hmac_key = rte_tel_data_alloc();
	if (!hmac_key) {
		plt_err("Could not allocate space for hmac key");
		return -ENOMEM;
	}

	rte_tel_data_start_array(hmac_key, RTE_TEL_U64_VAL);
	for (j = 0; j < RTE_DIM(in_sa->hmac_key); j++)
		rte_tel_data_add_array_u64(hmac_key, in_sa->hmac_key[j]);

	snprintf(str, sizeof(str), "insa_hkey_%u", i);
	rte_tel_data_add_dict_container(d, str, hmac_key, 0);

	return 0;
}

static int
ethdev_sec_tel_handle_info(const char *cmd __rte_unused, const char *params,
			   struct rte_tel_data *d)
{
	struct cnxk_eth_sec_sess *eth_sec, *tvar;
	char name[RTE_ETH_NAME_MAX_LEN];
	struct rte_eth_dev *eth_dev;
	struct cnxk_eth_dev *dev;
	uint16_t port_id;
	char *end_p;
	uint32_t i;
	int ret;

	port_id = strtoul(params, &end_p, 0);
	if (errno != 0)
		return -EINVAL;

	if (*end_p != '\0')
		plt_err("Extra parameters passed to telemetry, ignoring it");

	if (!rte_eth_dev_is_valid_port(port_id))
		return -EINVAL;

	eth_dev = &rte_eth_devices[port_id];
	if (!eth_dev) {
		plt_err("No ethdev of name %s available", name);
		return -EINVAL;
	}

	dev = cnxk_eth_pmd_priv(eth_dev);

	rte_tel_data_start_dict(d);

	rte_tel_data_add_dict_int(d, "nb_outb_sa", dev->outb.nb_sess);

	i = 0;
	if (dev->tx_offloads & DEV_TX_OFFLOAD_SECURITY) {
		tvar = NULL;
		RTE_TAILQ_FOREACH_SAFE(eth_sec, &dev->outb.list, entry, tvar) {
			ret = copy_outb_sa(d, i++, eth_sec->sa);
			if (ret < 0)
				return ret;
		}
	}

	rte_tel_data_add_dict_int(d, "nb_inb_sa", dev->inb.nb_sess);

	i = 0;
	if (dev->rx_offloads & DEV_RX_OFFLOAD_SECURITY) {
		tvar = NULL;
		RTE_TAILQ_FOREACH_SAFE(eth_sec, &dev->inb.list, entry, tvar) {
			ret = copy_inb_sa(d, i++, eth_sec->sa);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

RTE_INIT(cnxk_cryptodev_init_telemetry)
{
	rte_telemetry_register_cmd("/cnxk/ipsec/info",
				   ethdev_sec_tel_handle_info,
				   "Returns ipsec info. Parameters: port id");
}
