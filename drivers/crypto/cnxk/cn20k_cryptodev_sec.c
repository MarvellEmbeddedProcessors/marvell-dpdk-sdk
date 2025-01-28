/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include <rte_security.h>

#include "cn20k_cryptodev_ops.h"
#include "cn20k_cryptodev_sec.h"
#include "cnxk_cryptodev_ops.h"

static int
cn20k_sec_session_create(void *dev, struct rte_security_session_conf *conf,
			 struct rte_security_session *sess)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(conf);
	RTE_SET_USED(sess);

	return -ENOTSUP;
}

static int
cn20k_sec_session_destroy(void *dev, struct rte_security_session *sec_sess)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(sec_sess);

	return -EINVAL;
}

static unsigned int
cn20k_sec_session_get_size(void *dev __rte_unused)
{
	return 0;
}

static int
cn20k_sec_session_stats_get(void *dev, struct rte_security_session *sec_sess,
			    struct rte_security_stats *stats)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(sec_sess);
	RTE_SET_USED(stats);

	return -ENOTSUP;
}

static int
cn20k_sec_session_update(void *dev, struct rte_security_session *sec_sess,
			 struct rte_security_session_conf *conf)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(sec_sess);
	RTE_SET_USED(conf);

	return -ENOTSUP;
}

static int
cn20k_cryptodev_sec_rx_inject_configure(void *device, uint16_t port_id, bool enable)
{
	RTE_SET_USED(device);
	RTE_SET_USED(port_id);
	RTE_SET_USED(enable);

	return -ENOTSUP;
}

#if defined(RTE_ARCH_ARM64)
static uint16_t
cn20k_cryptodev_sec_inb_rx_inject(void *dev, struct rte_mbuf **pkts,
				  struct rte_security_session **sess, uint16_t nb_pkts)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(pkts);
	RTE_SET_USED(sess);
	RTE_SET_USED(nb_pkts);

	return 0;
}
#else
uint16_t __rte_hot
cn20k_cryptodev_sec_inb_rx_inject(void *dev, struct rte_mbuf **pkts,
				  struct rte_security_session **sess, uint16_t nb_pkts)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(sess);
	RTE_SET_USED(nb_pkts);

	return 0;
}
#endif

/* Update platform specific security ops */
void
cn20k_sec_ops_override(void)
{
	/* Update platform specific ops */
	cnxk_sec_ops.session_create = cn20k_sec_session_create;
	cnxk_sec_ops.session_destroy = cn20k_sec_session_destroy;
	cnxk_sec_ops.session_get_size = cn20k_sec_session_get_size;
	cnxk_sec_ops.session_stats_get = cn20k_sec_session_stats_get;
	cnxk_sec_ops.session_update = cn20k_sec_session_update;
	cnxk_sec_ops.inb_pkt_rx_inject = cn20k_cryptodev_sec_inb_rx_inject;
	cnxk_sec_ops.rx_inject_configure = cn20k_cryptodev_sec_rx_inject_configure;
}
