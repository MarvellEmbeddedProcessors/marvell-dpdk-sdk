/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _TEST_CASES_
#define _TEST_CASES_

#include <stdint.h>

#include "ucode/se.h"

#define MAX_DLEN	16384

struct ipsec_test_data {
	struct {
		uint8_t data[32];
	} key;
	struct {
		uint8_t data[64];
	} auth_key;

	struct {
		uint8_t data[MAX_DLEN];
		unsigned int len;
	} input_text;

	struct {
		uint8_t data[MAX_DLEN];
		unsigned int len;
	} output_text;

	struct {
		uint8_t data[4];
		unsigned int len;
	} salt;

	struct {
		uint8_t data[16];
	} iv;

	struct rte_security_ipsec_xform ipsec_xform;

	bool aead;

	bool aes_gmac;

	bool auth_only;

	/* Antireplay packet */
	bool ar_packet;

	union {
		struct {
			struct rte_crypto_sym_xform cipher;
			struct rte_crypto_sym_xform auth;
		} chain;
		struct rte_crypto_sym_xform aead;
	} xform;
};

struct test_case_params {
	uint8_t opcode_major;
	uint8_t opcode_minor;
	uint16_t dlen;
	void *dptr;
	void *rptr;
	void *cptr;
	uint8_t ctx_val;
	bool verify_output;
	void *sec_session;
	struct ipsec_test_data aes_cbc_hmac_sha256;
};


struct test_case_params test_cases[] = {
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 128,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 0,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 32,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 64,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 512,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 1024,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 2048,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 8192,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 0,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 64,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 128,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 256,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 512,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1024,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1344,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 2048,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 8192,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 64,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 128,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 256,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 512,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1024,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1536,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 2048,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 8192,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC,
		.opcode_minor = 0,
		.dlen = 124,
		.ctx_val = 1,
		.verify_output = true,
		.aes_cbc_hmac_sha256 = {
			.key = {
				.data = {
					0x00, 0x04, 0x05, 0x01, 0x23, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0f, 0x00, 0x00,
				},
			},
			.auth_key = {
				.data = {
					0xde, 0x34, 0x56, 0x00, 0x00, 0x00, 0x78, 0x00,
					0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
					0x10, 0x30, 0x40, 0x00, 0x01, 0x02, 0x03, 0x04,
					0x0a, 0x0b, 0x0c, 0x0d, 0x05, 0x06, 0x07, 0x08,
				},
			},
			.input_text = {
				.data = {
					/* IP */
					0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00,
					0x1f, 0x11, 0x17, 0x8b, 0xc0, 0xa8, 0x01, 0x6f,
					0xc0, 0xa8, 0x01, 0x70,

					/* UDP */
					0x00, 0x09, 0x00, 0x09, 0x00, 0x1e, 0x00, 0x00,
					0xbe, 0x9b, 0xe9, 0x55, 0x00, 0x00, 0x00, 0x21,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				.len = 50,
			},
			.output_text = {
				.data = {
					/* IP - outer header */
					0x45, 0x00, 0x00, 0x7c, 0x00, 0x01, 0x00, 0x00,
					0x40, 0x32, 0x52, 0x4d, 0x14, 0x00, 0x00, 0x01,
					0x14, 0x00, 0x00, 0x02,

					/* ESP */
					0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,

					/* IV */
					0x34, 0x12, 0x67, 0x45, 0xff, 0xff, 0x00, 0x00,
					0x20, 0xbf, 0xe8, 0x39, 0x00, 0x00, 0x00, 0x00,

					/* Data */
					0x67, 0xb5, 0x46, 0x6e, 0x78, 0x17, 0xd3, 0x5a,
					0xac, 0x62, 0x62, 0x62, 0xb0, 0x57, 0x9b, 0x09,
					0x19, 0x4f, 0x06, 0x59, 0xc8, 0xb0, 0x30, 0x65,
					0x1f, 0x45, 0x57, 0x41, 0x72, 0x17, 0x28, 0xe9,
					0xad, 0x50, 0xbe, 0x44, 0x1d, 0x2d, 0x9a, 0xd0,
					0x48, 0x75, 0x0d, 0x1c, 0x8d, 0x24, 0xa8, 0x6f,
					0x6b, 0x24, 0xb6, 0x5d, 0x43, 0x1e, 0x55, 0xf0,
					0xf7, 0x14, 0x1f, 0xf2, 0x61, 0xd4, 0xe0, 0x30,
					0x16, 0xbe, 0x1b, 0x5c, 0xcc, 0xb7, 0x66, 0x1c,
					0x47, 0xad, 0x07, 0x6c, 0xd5, 0xcb, 0xce, 0x6c,
				},
				.len = 124,
			},
			.iv = {
				.data = {
					0x34, 0x12, 0x67, 0x45, 0xff, 0xff, 0x00, 0x00,
					0x20, 0xbf, 0xe8, 0x39, 0x00, 0x00, 0x00, 0x00,
				},
			},

			.ipsec_xform = {
				.spi = 52,
				.options.esn = 0,
				.options.udp_encap = 0,
				.options.copy_dscp = 0,
				.options.copy_flabel = 0,
				.options.copy_df = 0,
				.options.dec_ttl = 0,
				.options.ecn = 0,
				.options.stats = 0,
				.options.tunnel_hdr_verify = 0,
				.options.iv_gen_disable = 0,
				.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
				.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
				.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
				.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				.replay_win_sz = 0,
			},

			.aead = false,

			.xform = {
				.chain.cipher = {
					.next = NULL,
					.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
					.cipher = {
						.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
						.algo = RTE_CRYPTO_CIPHER_AES_CBC,
						.key.length = 16,
						.iv.length = 16,
					},
				},
				.chain.auth = {
					.next = NULL,
					.type = RTE_CRYPTO_SYM_XFORM_AUTH,
					.auth = {
						.op = RTE_CRYPTO_AUTH_OP_GENERATE,
						.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
						.key.length = 32,
						.digest_length = 16,
					},
				},
			},
		},
	},
	{
		.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC,
		.opcode_minor = 0,
		.dlen = 124,
		.ctx_val = 1,
		.aes_cbc_hmac_sha256 = {
			.key = {
				.data = {
					0x00, 0x04, 0x05, 0x01, 0x23, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0f, 0x00, 0x00,
				},
			},
			.auth_key = {
				.data = {
					0xde, 0x34, 0x56, 0x00, 0x00, 0x00, 0x78, 0x00,
					0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
					0x10, 0x30, 0x40, 0x00, 0x01, 0x02, 0x03, 0x04,
					0x0a, 0x0b, 0x0c, 0x0d, 0x05, 0x06, 0x07, 0x08,
				},
			},
			.input_text = {
				.data = {
					/* IP */
					0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00,
					0x1f, 0x11, 0x17, 0x8b, 0xc0, 0xa8, 0x01, 0x6f,
					0xc0, 0xa8, 0x01, 0x70,

					/* UDP */
					0x00, 0x09, 0x00, 0x09, 0x00, 0x1e, 0x00, 0x00,
					0xbe, 0x9b, 0xe9, 0x55, 0x00, 0x00, 0x00, 0x21,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				.len = 50,
			},
			.output_text = {
				.data = {
					/* IP - outer header */
					0x45, 0x00, 0x00, 0x7c, 0x00, 0x01, 0x00, 0x00,
					0x40, 0x32, 0x52, 0x4d, 0x14, 0x00, 0x00, 0x01,
					0x14, 0x00, 0x00, 0x02,

					/* ESP */
					0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,

					/* IV */
					0x34, 0x12, 0x67, 0x45, 0xff, 0xff, 0x00, 0x00,
					0x20, 0xbf, 0xe8, 0x39, 0x00, 0x00, 0x00, 0x00,

					/* Data */
					0x67, 0xb5, 0x46, 0x6e, 0x78, 0x17, 0xd3, 0x5a,
					0xac, 0x62, 0x62, 0x62, 0xb0, 0x57, 0x9b, 0x09,
					0x19, 0x4f, 0x06, 0x59, 0xc8, 0xb0, 0x30, 0x65,
					0x1f, 0x45, 0x57, 0x41, 0x72, 0x17, 0x28, 0xe9,
					0xad, 0x50, 0xbe, 0x44, 0x1d, 0x2d, 0x9a, 0xd0,
					0x48, 0x75, 0x0d, 0x1c, 0x8d, 0x24, 0xa8, 0x6f,
					0x6b, 0x24, 0xb6, 0x5d, 0x43, 0x1e, 0x55, 0xf0,
					0xf7, 0x14, 0x1f, 0xf2, 0x61, 0xd4, 0xe0, 0x30,
					0x16, 0xbe, 0x1b, 0x5c, 0xcc, 0xb7, 0x66, 0x1c,
					0x47, 0xad, 0x07, 0x6c, 0xd5, 0xcb, 0xce, 0x6c,
				},
				.len = 124,
			},
			.iv = {
				.data = {
					0x34, 0x12, 0x67, 0x45, 0xff, 0xff, 0x00, 0x00,
					0x20, 0xbf, 0xe8, 0x39, 0x00, 0x00, 0x00, 0x00,
				},
			},

			.ipsec_xform = {
				.spi = 52,
				.options.esn = 0,
				.options.udp_encap = 0,
				.options.copy_dscp = 0,
				.options.copy_flabel = 0,
				.options.copy_df = 0,
				.options.dec_ttl = 0,
				.options.ecn = 0,
				.options.stats = 0,
				.options.tunnel_hdr_verify = 0,
				.options.iv_gen_disable = 0,
				.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
				.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP,
				.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL,
				.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				.replay_win_sz = 0,
			},

			.aead = false,

			.xform = {
				.chain.cipher = {
					.next = NULL,
					.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
					.cipher = {
						.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
						.algo = RTE_CRYPTO_CIPHER_AES_CBC,
						.key.length = 16,
						.iv.length = 16,
					},
				},
				.chain.auth = {
					.next = NULL,
					.type = RTE_CRYPTO_SYM_XFORM_AUTH,
					.auth = {
						.op = RTE_CRYPTO_AUTH_OP_GENERATE,
						.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
						.key.length = 32,
						.digest_length = 16,
					},
				},
			},
		},
	},
};


#endif /* _TEST_CASES_ */
