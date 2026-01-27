/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2026 Marvell.
 */
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_common.h>
#include <rte_string_fns.h>

#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "flow.h"
#include "parser.h"

#define PARSE_DELIMITER		" \f\n\r\t\v"
static int
parse_tokenize_string(char *string, char *tokens[], uint32_t *n_tokens)
{
	uint32_t i;

	if ((string == NULL) ||
	    (tokens == NULL) ||
	    (*n_tokens < 1))
		return -EINVAL;

	for (i = 0; i < *n_tokens; i++) {
		tokens[i] = strtok_r(string, PARSE_DELIMITER, &string);
		if (tokens[i] == NULL)
			break;
	}

	if ((i == *n_tokens) &&
	    (NULL != strtok_r(string, PARSE_DELIMITER, &string)))
		return -E2BIG;

	*n_tokens = i;
	return 0;
}

int
parse_ipv4_addr(const char *token, struct in_addr *ipv4, uint32_t *mask)
{
	char ip_str[INET_ADDRSTRLEN] = {0};
	char *pch;

	pch = strchr(token, '/');
	if (pch != NULL) {
		strlcpy(ip_str, token,
			RTE_MIN((unsigned int long)(pch - token + 1),
			sizeof(ip_str)));
		pch += 1;
		if (is_str_num(pch) != 0)
			return -EINVAL;
		if (mask)
			*mask = atoi(pch);
	} else {
		strlcpy(ip_str, token, sizeof(ip_str));
		if (mask)
			*mask = 0;
	}
	if (strlen(ip_str) >= INET_ADDRSTRLEN)
		return -EINVAL;

	if (inet_pton(AF_INET, ip_str, ipv4) != 1)
		return -EINVAL;

	return 0;
}

int
parse_ipv6_addr(const char *token, struct rte_ipv6_addr *ipv6, uint32_t *mask)
{
	char ip_str[256] = {0};
	char *pch;

	pch = strchr(token, '/');
	if (pch != NULL) {
		strlcpy(ip_str, token,
			RTE_MIN((unsigned int long)(pch - token + 1),
				sizeof(ip_str)));
		pch += 1;
		if (is_str_num(pch) != 0)
			return -EINVAL;
		if (mask)
			*mask = atoi(pch);
	} else {
		strlcpy(ip_str, token, sizeof(ip_str));
		if (mask)
			*mask = 0;
	}

	if (strlen(ip_str) >= INET6_ADDRSTRLEN)
		return -EINVAL;

	if (inet_pton(AF_INET6, ip_str, ipv6) != 1)
		return -EINVAL;

	return 0;
}

int
parse_range(const char *token, uint16_t *low, uint16_t *high)
{
	char ch;
	char num_str[20];
	uint32_t pos;
	int range_low = -1;
	int range_high = -1;

	if (!low || !high)
		return -1;

	memset(num_str, 0, 20);
	pos = 0;

	while ((ch = *token++) != '\0') {
		if (isdigit(ch)) {
			if (pos >= 19)
				return -1;
			num_str[pos++] = ch;
		} else if (ch == ':') {
			if (range_low != -1)
				return -1;
			range_low = atoi(num_str);
			memset(num_str, 0, 20);
			pos = 0;
		}
	}

	if (strlen(num_str) == 0)
		return -1;

	range_high = atoi(num_str);

	*low = (uint16_t)range_low;
	*high = (uint16_t)range_high;

	return 0;
}

/* flow add parse */
struct cfg_flow_add_cfg_item {
	cmdline_fixed_string_t flow_keyword;
	cmdline_multi_string_t multi_string;
};

static void
cfg_flow_add_cfg_item_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, void *data)
{
	struct cfg_flow_add_cfg_item *params = parsed_result;
	char *tokens[32];
	uint32_t n_tokens = RTE_DIM(tokens);
	struct parse_status *status = (struct parse_status *)data;

	APP_CHECK(parse_tokenize_string(
		params->multi_string, tokens, &n_tokens) == 0,
		status, "too many arguments\n");
	if (status->status < 0)
		return;

	parse_flow_tokens(tokens, n_tokens, status);
}

static cmdline_parse_token_string_t cfg_flow_add_flow_str =
	TOKEN_STRING_INITIALIZER(struct cfg_flow_add_cfg_item,
		flow_keyword, "flow");

static cmdline_parse_token_string_t cfg_flow_add_multi_str =
	TOKEN_STRING_INITIALIZER(struct cfg_flow_add_cfg_item, multi_string,
		TOKEN_STRING_MULTI);

cmdline_parse_inst_t cfg_flow_add_rule = {
	.f = cfg_flow_add_cfg_item_parsed,
	.data = NULL,
	.help_str = "",
	.tokens = {
		(void *) &cfg_flow_add_flow_str,
		(void *) &cfg_flow_add_multi_str,
		NULL,
	},
};

/** set of cfg items */
cmdline_parse_ctx_t ipsec_ctx[] = {
	(cmdline_parse_inst_t *)&cfg_flow_add_rule,
	NULL,
};

int
parse_cfg_file(const char *cfg_filename)
{
	struct cmdline *cl = cmdline_file_new(ipsec_ctx, "", "/dev/null");
	FILE *f = fopen(cfg_filename, "r");
	char str[1024] = {0}, *get_s = NULL;
	uint32_t line_num = 0;
	struct parse_status status = {0};

	if (f == NULL) {
		rte_panic("Error: invalid file descriptor %s\n", cfg_filename);
		goto error_exit;
	}

	if (cl == NULL) {
		rte_panic("Error: cannot create cmdline instance\n");
		goto error_exit;
	}

	cfg_flow_add_rule.data = &status;

	do {
		char oneline[1024];
		char *pos;

		get_s = fgets(oneline, 1024, f);

		if (!get_s)
			break;

		line_num++;

		if (strlen(oneline) > 1022) {
			rte_panic("%s:%u: error: "
				"the line contains more characters the parser can handle\n",
				cfg_filename, line_num);
			goto error_exit;
		}

		/* process comment char '#' */
		if (oneline[0] == '#')
			continue;

		pos = strchr(oneline, '#');
		if (pos != NULL)
			*pos = '\0';

		/* process line concatenator '\' */
		pos = strchr(oneline, 92);
		if (pos != NULL) {
			if (pos != oneline + strlen(oneline) - 2) {
				rte_panic("%s:%u: error: "
					"no character should exist after '\\'\n",
					cfg_filename, line_num);
				goto error_exit;
			}

			*pos = '\0';

			if (strlen(oneline) + strlen(str) > 1022) {
				rte_panic("%s:%u: error: "
					"the concatenated line contains more characters the parser can handle\n",
					cfg_filename, line_num);
				goto error_exit;
			}

			strcpy(str + strlen(str), oneline);
			continue;
		}

		/* copy the line to str and process */
		if (strlen(oneline) + strlen(str) > 1022) {
			rte_panic("%s:%u: error: "
				"the line contains more characters the parser can handle\n",
				cfg_filename, line_num);
			goto error_exit;
		}
		strcpy(str + strlen(str), oneline);

		str[strlen(str)] = '\n';
		if (cmdline_parse(cl, str) < 0) {
			rte_panic("%s:%u: error: parsing \"%s\" failed\n",
				cfg_filename, line_num, str);
			goto error_exit;
		}

		if (status.status < 0) {
			rte_panic("%s:%u: error: %s", cfg_filename,
				line_num, status.parse_msg);
			goto error_exit;
		}

		memset(str, 0, 1024);
	} while (1);

	cmdline_free(cl);
	fclose(f);

	return 0;

error_exit:
	if (cl)
		cmdline_free(cl);
	if (f)
		fclose(f);

	return -1;
}
