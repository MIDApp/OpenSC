/*
 * card-itacns.c: Support for Italian CNS
 *
 * Copyright (C) 2008-2010	Emanuele Pucciarelli <ep@acm.org>
 * Copyright (C) 2005  		ST Incard srl, Giuseppe Amato <giuseppe dot amato at st dot com>, <midori3@gmail.com>
 * Copyright (C) 2002  		Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright (C) 2001  		Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Specifications for the development of this driver come from:
 * http://www.cnipa.gov.it/html/docs/CNS%20Functional%20Specification%201.1.5_11012010.pdf
 */

#include "internal.h"
#include "cardctl.h"
#include "itacns.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#ifdef ENABLE_SM
#ifdef ENABLE_OPENSSL
#define ENABLE_ITACNS_SM
#endif
#endif

#ifdef ENABLE_ITACNS_SM
#include <openssl/evp.h>
#endif

#define ITACNS_MAX_PAYLOAD 0xff

static const struct sc_card_operations *default_ops = NULL;

static struct sc_card_operations itacns_ops;
static struct sc_card_driver itacns_drv = {
	"Italian CNS",
	"itacns",
	&itacns_ops,
	NULL, 0, NULL
};

/*
 * Card matching
 */


/* List of ATR's for "hard" matching. */
static struct sc_atr_table itacns_atrs[] = {
	{ "3b:f4:18:00:ff:81:31:80:55:00:31:80:00:c7", NULL, NULL,
		SC_CARD_TYPE_ITACNS_CIE_V1, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL}
};

/* Output debug info */
#define matchdebug(idx, c) do { \
	sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, \
		"Matching %x against atr[%d] == %x", c, idx, atr[idx]); \
	} while(0);

/* Check that we are not looking at values beyond the ATR's length.
 * If we are, then the card does not match. */
#define itacns_atr_l(idx) do {if (idx >= card->atr.len) return 0;} while(0);

/* Match byte exactly and increment index. */
#define itacns_atr_match(idx, c) do { \
		itacns_atr_l(idx); \
		matchdebug(idx, c); \
		if (((u8)atr[idx]) != c) return 0; \
		idx++; \
	} while(0);

/* Match masked bits and increment index. */
#define itacns_atr_mmatch(idx, c, mask) do { \
		itacns_atr_l(idx); \
		if ((((u8)atr[idx]) & mask) != c) return 0; \
		idx ++; \
	} while(0);

/* Macro to access private driver data. */
#define DRVDATA(card) ((itacns_drv_data_t *) card->drv_data)

static int
itacns_sm_open(struct sc_card *);

static int
itacns_sm_get_wrapped_apdu(struct sc_card *, struct sc_apdu *, struct sc_apdu **);

static int
itacns_sm_free_wrapped_apdu(struct sc_card *, struct sc_apdu *, struct sc_apdu **);

static int itacns_match_cns_card(sc_card_t *card, unsigned int i)
{
	unsigned char *atr = card->atr.value;
	sc_context_t *ctx;
	ctx = card->ctx;


	itacns_atr_match(i, 0x01); /* H7 */
	i += 2; /* H8, H9 */
	itacns_atr_match(i, 'C'); /* H10 */
	itacns_atr_match(i, 'N'); /* H11 */
	itacns_atr_match(i, 'S'); /* H12 */

	/* H13 */
	/* Version byte: h.l, h in the high nibble, l in the low nibble. */
	if(card->driver) {
		DRVDATA(card)->cns_version = atr[i];
	}
	/* Warn if the version is not 1.0. */
	if(atr[i] != 0x10) {
		char version[8];
		snprintf(version, sizeof(version), "%d.%d", (atr[i] >> 4) & 0x0f, atr[i] & 0x0f);
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "CNS card version %s; no official specifications "
			"are published. Proceeding anyway.\n", version);
	}
	i++;

	itacns_atr_match(i, 0x31); /* H14 */
	itacns_atr_match(i, 0x80); /* H15 */

	card->type = SC_CARD_TYPE_ITACNS_CNS;

	return 1;
}

static int itacns_match_cie_card(sc_card_t *card, unsigned int i)
{
	unsigned char *atr = card->atr.value;
	sc_context_t *ctx;
	ctx = card->ctx;

	itacns_atr_match(i, 0x02); /* H7 */
	itacns_atr_match(i, 'I'); /* H8 */
	itacns_atr_match(i, 'T'); /* H9 */
	itacns_atr_match(i, 'I'); /* H10 */
	itacns_atr_match(i, 'D'); /* H11 */
	itacns_atr_match(i, 0x20); /* H12 */
	itacns_atr_match(i, 0x20); /* H13 */
	itacns_atr_match(i, 0x31); /* H14 */
	itacns_atr_match(i, 0x80); /* H15 */

	card->type = SC_CARD_TYPE_ITACNS_CIE_V2;

	return 1;
}

static int itacns_match_card(sc_card_t *card)
{
	unsigned int i = 0;
	int r;
	unsigned char *atr = card->atr.value;
	int td1_idx;
	sc_context_t *ctx;
	ctx = card->ctx;

	/* Try table first */
	r = _sc_match_atr(card, itacns_atrs, &card->type);
	if(r >= 0) return 1;

	/* The ATR was not recognized; try to match it
	   according to the official specs. */

	/* Check ATR up to byte H6 */
	itacns_atr_match(i, 0x3b); /* TS */
	itacns_atr_mmatch(i, 0x8f, 0x8f); /* T0 */
	/* TA1, TB1, TC1 */
	if(atr[1] & 0x40) i++;
	if(atr[1] & 0x20) i++;
	if(atr[1] & 0x10) i++;
	/* TD1 */
	td1_idx = i;
	itacns_atr_mmatch(i, 0x81, 0x8f);
	/* TA2, TB2, TC2 */
	if(atr[td1_idx] & 0x40) i++;
	if(atr[td1_idx] & 0x20) i++;
	if(atr[td1_idx] & 0x10) i++;
	/* TD2 */
	itacns_atr_match(i, 0x31);
	i += 2; /* TA3, TB3 */
	itacns_atr_match(i, 0x00); /* H1 */
	itacns_atr_match(i, 0x6b); /* H2 */
	/* Store interesting data */
	if(card->driver) {
		DRVDATA(card)->ic_manufacturer_code = card->atr.value[i];
		DRVDATA(card)->mask_manufacturer_code = card->atr.value[i+1];
		DRVDATA(card)->os_version_h = card->atr.value[i+2];
		DRVDATA(card)->os_version_l = card->atr.value[i+3];
	}
	i += 4; /* H3, H4, H5, H6 */

	/* Check final part. */
	if (itacns_match_cns_card(card, i)) return 1;
	if (itacns_match_cie_card(card, i)) return 1;

	/* No card type was matched. */
	return 0;
}

/*
 * Initialization and termination
 */

static int itacns_init(sc_card_t *card)
{
	unsigned long	flags;

	SC_FUNC_CALLED(card->ctx, 1);

	card->name = "CNS card";
	card->cla = 0x00;

	card->drv_data = calloc(1, sizeof(itacns_drv_data_t));

	/* Match ATR again to find the card data. */
	itacns_match_card(card);

	/* Set up algorithm info. */
	flags = SC_ALGORITHM_NEED_USAGE
		/*| SC_ALGORITHM_RSA_RAW*/
		| SC_ALGORITHM_RSA_HASHES
		| SC_ALGORITHM_RSA_PAD_PKCS1
		;
	_sc_card_add_rsa_alg(card, 1024, flags, 0);

#ifdef ENABLE_ITACNS_SM
	card->sm_ctx.ops.open = itacns_sm_open;
  	card->sm_ctx.ops.get_sm_apdu = itacns_sm_get_wrapped_apdu;
	card->sm_ctx.ops.free_sm_apdu = itacns_sm_free_wrapped_apdu;

	card->sm_ctx.ops.open(card);
#endif

	return 0;
}

static int itacns_finish(struct sc_card *card)
{
	if(card->drv_data) {
		free(card->drv_data);
	}
	return 0;
}



/*
 * Restore the indicated SE
 */
static int itacns_restore_security_env(sc_card_t *card, int se_num)
{
	sc_apdu_t apdu;
	int	r;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	SC_FUNC_CALLED(card->ctx, 1);

	/*
	 * The Italian CNS requires a 0-valued Lc byte at the end of the APDU
	 * (see paragraph 13.14 of the Functional Specification), but since
	 * it is invalid, we "cheat" and pretend it's a Le byte.
	 *
	 * For this workaround, we must allocate and supply a response buffer,
	 * even though we know it will not be used (we don't even check it).
	 */

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x22, 0xF3, se_num);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * Set the security context
 * Things get a little messy here. It seems you cannot do any
 * crypto without a security environment - but there isn't really
 * a way to specify the security environment in PKCS15.
 * What I'm doing here (for now) is to assume that for a key
 * object with ID 0xNN there is always a corresponding SE object
 * with the same ID.
 * XXX Need to find out how the Aladdin drivers do it.
 */
static int next_signature_protected = 0;

static int itacns_set_security_env(sc_card_t *card,
		    const sc_security_env_t *env, int se_num)
{
	sc_apdu_t apdu;
	u8	data[3];
	int	key_id, r;
	
	/* Do not complain about se_num; the argument is part of the API. */
	(void) se_num;

	assert(card != NULL && env != NULL);

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	 || env->key_ref_len != 1) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"No or invalid key reference\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	key_id = env->key_ref[0];

	/* CIE v1 cards need to restore security environment 0x30; all the others
	   so far want 0x03. */
	r = itacns_restore_security_env(card,
		(card->type == SC_CARD_TYPE_ITACNS_CIE_V1 ? 0x30 : 0x03));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF1, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		apdu.p2 = 0xA4;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
		"Setting sec env for key_id=%d\n", key_id);

	data[0] = 0x83;
	data[1] = 0x01;
	data[2] = key_id;
	apdu.lc = apdu.datalen = 3;
	apdu.data = data;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card returned error");

	if (key_id >= 0x10) {
		sc_log(card->ctx, "Next signature is protected");
		next_signature_protected = 1;
	} else {
		next_signature_protected = 0;
	}

	SC_FUNC_RETURN(card->ctx, 1, r);
}

/*
 * The 0x80 thing tells the card it's okay to search parent
 * directories as well for the referenced object.
 * This is necessary for some Italian CNS cards, and to be avoided
 * for others. Right now it seems that it is only needed with
 * cards by STIncard.
 */

static int
itacns_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
		 int *tries_left)
{
	data->flags |= SC_PIN_CMD_NEED_PADDING;
	/* Enable backtracking for STIncard cards. */
	if(DRVDATA(card)->mask_manufacturer_code == ITACNS_MASKMAN_STINCARD) {
		data->pin_reference |= 0x80;
	}

	/* FIXME: the following values depend on what pin length was
	 * used when creating the BS objects */
	if (data->pin1.max_length == 0)
		data->pin1.max_length = 8;
	if (data->pin2.max_length == 0)
		data->pin2.max_length = 8;
	int rv;
	if (next_signature_protected) {
		rv = SC_ERROR_CLASS_NOT_SUPPORTED;
	} else {
		rv = default_ops->pin_cmd(card, data, tries_left);
	}
	if (rv == SC_ERROR_CLASS_NOT_SUPPORTED 
		&& card->sm_ctx.sm_mode != SM_MODE_TRANSMIT) {
		int saved_sm_mode = card->sm_ctx.sm_mode;
		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
		rv = default_ops->pin_cmd(card, data, tries_left);
		card->sm_ctx.sm_mode = saved_sm_mode;
	}
	return rv;
}

static int itacns_compute_signature(struct sc_card *card,
		const u8 * data, size_t datalen,
		u8 * out, size_t outlen) {
	int rv = 0;
	if (next_signature_protected) {
		sc_log(card->ctx, "Using protected signature directly");
		int saved_sm_mode = card->sm_ctx.sm_mode;
		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
		rv = default_ops->compute_signature(card, data, datalen, out, outlen);
		card->sm_ctx.sm_mode = 0;
		return rv;
	}
	rv = default_ops->compute_signature(card, data, datalen, out, outlen);
	if (rv == SC_ERROR_CLASS_NOT_SUPPORTED 
		&& card->sm_ctx.sm_mode != SM_MODE_TRANSMIT) {
		int saved_sm_mode = card->sm_ctx.sm_mode;
		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
		rv = itacns_compute_signature(card, data, datalen, out, outlen);
		card->sm_ctx.sm_mode = saved_sm_mode;
	}		
	return rv;
}

static int itacns_read_binary(sc_card_t *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	size_t already_read = 0;
	int requested;
	int r;
	while(1) {
		requested = count - already_read;
		if(requested > ITACNS_MAX_PAYLOAD)
			requested = ITACNS_MAX_PAYLOAD;
		r = default_ops->read_binary(card, idx+already_read,
			&buf[already_read], requested, flags);
		if(r < 0) return r;
		already_read += r;
		if (r == 0 || r < requested || already_read == count) {
			/* We have finished */
			return already_read;
		}
	}
}

static int itacns_list_files(sc_card_t *card, u8 *buf, size_t buflen) {
	struct sc_card_operations *list_ops;

	if (DRVDATA(card) && (DRVDATA(card)->mask_manufacturer_code
		== ITACNS_MASKMAN_SIEMENS)) {
		list_ops = sc_get_cardos_driver()->ops;
	} else {
		list_ops = sc_get_incrypto34_driver()->ops;
	}
	return list_ops->list_files(card, buf, buflen);
}

static void add_acl_entry(sc_file_t *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte) {
	case 0x00:
		method = SC_AC_NONE;
		break;
	case 0xFF:
	case 0x66:
		method = SC_AC_NEVER;
		break;
	default:
		if (byte > 0x1F) {
			method = SC_AC_UNKNOWN;
		} else {
			method = SC_AC_CHV;
			key_ref = byte;
		}
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static const int df_acl[9] = {
	-1,			/* LCYCLE (life cycle change) */
	SC_AC_OP_UPDATE,	/* UPDATE Objects */
	SC_AC_OP_WRITE,		/* APPEND Objects */

	SC_AC_OP_INVALIDATE,	/* DF */
	SC_AC_OP_REHABILITATE,	/* DF */
	SC_AC_OP_DELETE,	/* DF */

	SC_AC_OP_WRITE,		/* ADMIN DF */
	SC_AC_OP_CREATE,	/* Files */
	-1			/* Reserved */
};
static const int ef_acl[9] = {
	SC_AC_OP_READ,		/* Data */
	SC_AC_OP_UPDATE,	/* Data (write file content) */
	SC_AC_OP_WRITE,		/* */

	SC_AC_OP_INVALIDATE,	/* EF */
	SC_AC_OP_REHABILITATE,	/* EF */
	SC_AC_OP_ERASE,		/* (delete) EF */

	/* XXX: ADMIN should be an ACL type of its own, or mapped
	 * to erase */
	SC_AC_OP_ERASE,		/* ADMIN EF (modify meta information?) */
	-1,			/* INC (-> cylic fixed files) */
	-1			/* DEC */
};

static void parse_sec_attr(sc_file_t *file, const u8 *buf, size_t len)
{
	size_t i;
	const int *idx;

	idx = (file->type == SC_FILE_TYPE_DF) ?  df_acl : ef_acl;

	/* acl defaults to 0xFF if unspecified */
	for (i = 0; i < 9; i++) {
		if (idx[i] != -1) {
			add_acl_entry(file, idx[i],
				(u8)((i < len) ? buf[i] : 0xFF));
		}
	}
}

static int itacns_select_file(sc_card_t *card,
			      const sc_path_t *in_path,
			      sc_file_t **file)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = default_ops->select_file(card, in_path, file);
	if (r >= 0 && file) {
		parse_sec_attr((*file), (*file)->sec_attr,
			(*file)->sec_attr_len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


static struct sc_card_driver * sc_get_driver(void)
{
	if (!default_ops)
		default_ops = sc_get_iso7816_driver()->ops;
	itacns_ops = *default_ops;
	itacns_ops.match_card = itacns_match_card;
	itacns_ops.init = itacns_init;
	itacns_ops.finish = itacns_finish;
	itacns_ops.set_security_env = itacns_set_security_env;
	itacns_ops.restore_security_env = itacns_restore_security_env;
	itacns_ops.pin_cmd = itacns_pin_cmd;
	itacns_ops.read_binary = itacns_read_binary;
	itacns_ops.list_files = itacns_list_files;
	itacns_ops.select_file = itacns_select_file;
	itacns_ops.compute_signature = itacns_compute_signature;
	return &itacns_drv;
}

struct sc_card_driver * sc_get_itacns_driver(void)
{
	return sc_get_driver();
}

#ifdef ENABLE_ITACNS_SM

#define SC_DEBUG5(...) sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, __VA_ARGS__)
#define sc_error(ctx, ...) sc_debug(ctx, SC_LOG_DEBUG_NORMAL, __VA_ARGS__)

static unsigned char nibble(char in)
{
	if (in >= '0' && in <= '9')
		return in - '0';
	if (in >= 'A' && in <= 'F')
		return in - 'A' + 0x0a;
	if (in >= 'a' && in <= 'f')
		return in - 'a' + 0x0a;
	return 0xff;
}

const size_t des_bs = 8;

const u8 des_null_iv[] = {0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0};

#define CIPHER_TEST_RET(r, msg) {do \
    { \
        if(!(r)) {\
            EVP_CIPHER_CTX_cleanup(&ctx); \
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, -1, msg);\
        }\
    }\
while(0);}

static int
itacns_sm_open(struct sc_card *card)
{
	const unsigned char blank_key[] = "\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0" 
		"\0\0\0\0\0\0\0\0";
	       /* Load SM key. */

    scconf_block *drv_block, **blocks;
    drv_block = NULL;
	int i;
    for (i = 0; card->ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
									"card_driver", "itacns");
		if (blocks[0] != NULL)
			drv_block = blocks[0];
        free(blocks);
    }
	if(!drv_block) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid or missing card_driver itacns "
			"block in configuration file");
		memcpy(&card->sm_ctx.info.session.cns.symmetric_key, blank_key, sizeof(blank_key));
		return 1;
	}

	const char *hex_key = scconf_get_str(drv_block, "sm_key", "");

	if (strlen(hex_key) != 48) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid or missing SM key "
			"in configuration file");
		memcpy(&card->sm_ctx.info.session.cns.symmetric_key, blank_key, sizeof(blank_key));
		return 1;
	}

	/* convert hex */
	for(i=0; i+1 < 48; i+=2) {
		unsigned char h = nibble(hex_key[i]);
		unsigned char l = nibble(hex_key[i+1]);
		if (h > 0xf || l > 0xf) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid hex digit in SM key");
			return 1;
		}
		card->sm_ctx.info.session.cns.symmetric_key[i/2] = (h << 4) | l;
	}
	return 0;
}

static int compute_mac3(sc_card_t *card, u8 *outbuf, const u8 *inbuf, size_t len, const u8 *key)
{
	EVP_CIPHER_CTX ctx;
	u8 intermediate_iv[8];
	int outlen;
	int r, i;

	SC_FUNC_CALLED(card->ctx, 1);

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, len % des_bs, "Length must always be a multiple of 8");

	EVP_CIPHER_CTX_init(&ctx);
	r = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, key, des_null_iv);
	CIPHER_TEST_RET(r, "Could not init MAC3 ctx");
	r = EVP_EncryptUpdate(&ctx, intermediate_iv, &outlen, inbuf, des_bs);
	CIPHER_TEST_RET(r, "Could not do first round of MAC3 ctx");
	for(i=1; i<((len/des_bs)-1); i++) {
		u8 source[des_bs];
		memcpy(source, intermediate_iv, des_bs);
		r = EVP_EncryptInit_ex(&ctx, NULL, NULL, key, source);
		CIPHER_TEST_RET(r, "Could not init internal round of MAC3");
		r = EVP_EncryptUpdate(&ctx, intermediate_iv, &outlen, &inbuf[i*des_bs], des_bs);
		CIPHER_TEST_RET(r, "Could not update internal round of MAC3");
		CIPHER_TEST_RET(outlen == 8, "Weird length of output block in internal MAC3 round");
	}
	r = EVP_EncryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, key, intermediate_iv);
	CIPHER_TEST_RET(r, "Could not init final round of MAC3");
	r = EVP_EncryptUpdate(&ctx, outbuf, &outlen, &inbuf[i*des_bs], des_bs);
	CIPHER_TEST_RET(r, "Could not update final round of MAC3");

	r = EVP_CIPHER_CTX_cleanup(&ctx);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not clean up crypto context");

	return 0;
}

static int compute_sm_signature(sc_card_t *card, int sig_method,
	u8 *sig_out, const u8 *sig_in, const size_t sig_inlen,
	sc_apdu_t *apdu,
	u8 *random, const u8 *key)
{
	const size_t h_cla = 8;
	const size_t h_ins = 9;
	const size_t h_p1 = 10;
	const size_t h_p2 = 11;
	const size_t h_padding = 12;

	u8 * macblock = NULL;
	macblock = calloc(1, SC_MAX_APDU_BUFFER_SIZE);
	memcpy(macblock, random, 8);
	SC_DEBUG5("Computing sig w/ random: %x%x%x%x %x%x%x%x",
		random[0], random[1], random[2], random[3], 
		random[4], random[5], random[6], random[7]);
	SC_DEBUG5("Header block: %x %x %x %x\n", apdu->cla,
		apdu->ins, apdu->p1, apdu->p2);
	macblock[h_cla] = apdu->cla;
	macblock[h_ins] = apdu->ins;
	macblock[h_p1] = apdu->p1;
	macblock[h_p2] = apdu->p2;
	memset(&macblock[h_padding], 0, 4);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, (sig_inlen+16 > SC_MAX_APDU_BUFFER_SIZE),
		"Text block for signature is too long");
	memcpy(&macblock[16], sig_in, sig_inlen);
	int i = sig_inlen + 16;

	/* Padding */
	while(i % 8) {
		macblock[i++] = 0x00;
	}

	if(sig_method) {
		int r;
		SC_DEBUG5("Macblock length = %x\n", i);
		r = compute_mac3(card, sig_out, macblock, i, key);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not compute MAC3 signature");
	} else {
		sc_error(card->ctx, "Unknown SIG method %d", sig_method);
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	free(macblock);
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

static int do_3des(sc_card_t *card, const u8 *key, u8 *out, int *outlen, 
	const u8 *in, size_t inlen, 
	int enc)
{
	int r;
	EVP_CIPHER_CTX ctx;
	
	int bufpos;
	
	*outlen = 0;

	SC_FUNC_CALLED(card->ctx, 1);

	EVP_CIPHER_CTX_init(&ctx);
	r = EVP_CipherInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, NULL, NULL, -1);
	CIPHER_TEST_RET(r, "Could not init 3DES crypto (alg)");
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	r = EVP_CipherInit_ex(&ctx, NULL, NULL, key, des_null_iv, enc);
	CIPHER_TEST_RET(r, "Could not init 3DES crypto (params)");

	r = EVP_CipherUpdate(&ctx, out, &bufpos, in, inlen);
	CIPHER_TEST_RET(r, "Could not perform 3DES crypto");
	*outlen += bufpos;
	SC_DEBUG5("Current inlen: %d; current outlen: %d\n", inlen, *outlen);

	if((!enc)) {
		int lastbyte;
		r = EVP_CipherFinal_ex(&ctx, &out[*outlen], &bufpos);
		sc_debug(card->ctx, "EVP_CipherFinal_ex returned %d == 0x%x\n", r, r);
		CIPHER_TEST_RET(r, "Could not perform final round of 3DES crypto");
		*outlen += bufpos;

		/* Padding removal */
		if(card->ctx->debug >= 5) {
			sc_debug(card->ctx, "Current inlen: %d; current outlen: %d\n", inlen, *outlen);
			sc_apdu_log(card->ctx, SC_LOG_DEBUG_NORMAL, out, *outlen, 0);
		}
		
		lastbyte = *outlen;
		lastbyte--;
		while(out[lastbyte] == 0) {
			lastbyte--;
		}
		SC_DEBUG5("Last byte pos = %x; last bytes from that on = %x %x %x %x\n",
			lastbyte, out[lastbyte], out[lastbyte+1], out[lastbyte+2], out[lastbyte+3]);
		if(out[lastbyte] != 0x80) {
				CIPHER_TEST_RET(0, "Wrong padding in deciphered text");
		}
		*outlen = lastbyte;
	}
		
	SC_DEBUG5("Current inlen: %d; current outlen: %d\n", inlen, *outlen);
	r = EVP_CIPHER_CTX_cleanup(&ctx);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not clean up crypto context");
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

int sm_generic_send_transform(struct sc_card *card, struct sc_apdu *orig_apdu,
	struct sc_apdu *transformed_apdu, const u8 *key,
	int enc_method, int sig_method)
{
	int r;
	
	static int turn = 0;
	
	if (!key) {
        sc_error(card->ctx, "SM key not provided, cannot continue");
        return SC_ERROR_INTERNAL;
	}

	SC_DEBUG5("original resplen and LE: %d, %d", orig_apdu->resplen, orig_apdu->le);

	if(card->ctx->debug >= 5) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Original APDU:\n");
		sc_apdu_log(card->ctx, SC_LOG_DEBUG_NORMAL, orig_apdu->data, orig_apdu->datalen, 1);
	}

	/* Initialize permanent storage */
	SC_DEBUG5("allocating, turn %d\n", turn);
	turn++;

	if (!enc_method && !sig_method) {
		sc_error(card->ctx, "Must use at least one of signature or encryption with SM");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}

	if(sig_method) {
		/* Get challenge */
		int saved_sm_mode = card->sm_ctx.sm_mode;
		card->sm_ctx.sm_mode = 0;
		r = card->ops->get_challenge(card, card->sm_ctx.info.session.cns.card_challenge, 8);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not get challenge for SM");

		/* FIXME: make random */
		RAND_bytes(card->sm_ctx.info.session.cns.host_challenge, 8);
		r = card->ops->give_random(card, card->sm_ctx.info.session.cns.host_challenge,
			sizeof(card->sm_ctx.info.session.cns.host_challenge));
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not send challenge for SM");
		card->sm_ctx.sm_mode = saved_sm_mode;
	}

	/* TLV structure */
	u8 signable_object[1024];
	int signable_block_length;
	signable_object[1] = orig_apdu->datalen;
	u8 *pt = NULL;
	if (!enc_method) {
		/* Set up as a plain text block */
		signable_object[0] = 0x81;
		signable_object[1] = orig_apdu->datalen;
		signable_block_length = 2 + orig_apdu->datalen;
	} else if (enc_method) {
		signable_object[0] = 0x87;
		pt = calloc(1, SC_MAX_APDU_BUFFER_SIZE);
		int pt_len = orig_apdu->datalen;
		memcpy(pt, orig_apdu->data, orig_apdu->datalen);

		/* Padding */
		pt[pt_len++] = 0x80;
		while(pt_len % 8) {
			pt[pt_len++] = 0x00;
		}

		/* Encryption */
		int ctlen;
		r = do_3des(card, key, &signable_object[3], &ctlen, pt, pt_len, 1);
		free(pt);
		pt = NULL;
		signable_object[1] = (u8) ctlen+1;
		signable_object[2] = 0x01;
		signable_block_length = 3 + ctlen;
	} else {
		sc_error(card->ctx, "Unknown ENC method %d", enc_method);
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}


	/* Start preparing APDU */
	/* Pre-fill values for compute_sm_signature */
	transformed_apdu->cse = orig_apdu->cse;
	transformed_apdu->cla = (orig_apdu->cla & 0xf0) | 0x0c;
	transformed_apdu->ins = orig_apdu->ins;
	transformed_apdu->p1 = orig_apdu->p1;
	transformed_apdu->p2 = orig_apdu->p2;
	int output_size = signable_block_length;

	/*
	 * The answer will have 2 more bytes for the TLV crypto object structure,
	 * 1 for the initial padding indicator and up to 8 for the final padding.
	 */
	int expected_size = orig_apdu->le + 3 + 8;

	if(sig_method) {
		expected_size += 10;
		u8 mac[8];
		r = compute_sm_signature(card, sig_method,
			mac, signable_object, signable_block_length,
			transformed_apdu,
			card->sm_ctx.info.session.cns.card_challenge, key);
		signable_object[output_size++] = 0x8e;
		signable_object[output_size++] = 0x08;
		memcpy(&signable_object[output_size], mac, 8);
		output_size += 8;
	}

	SC_DEBUG5("Expected size is %d", expected_size);

	/* Don't expect a signature if the APDU wants no answer */
	if(orig_apdu->le == 0) expected_size = 0;

	transformed_apdu->cla = (orig_apdu->cla & 0xf0) | 0x0c;
	transformed_apdu->cse = orig_apdu->cse;
	transformed_apdu->ins = orig_apdu->ins;
	transformed_apdu->p1 = orig_apdu->p1;
	transformed_apdu->p2 = orig_apdu->p2;

	signable_object[output_size] = 0x00;
	SC_DEBUG5("Output size is %d", output_size);
	memcpy(transformed_apdu->data, signable_object, output_size);
	SC_DEBUG5("Memory was moved");
	transformed_apdu->lc = output_size;
	transformed_apdu->datalen = output_size;
	transformed_apdu->le = (expected_size < 256 ? expected_size : orig_apdu->le);
	SC_DEBUG5("Returning");

	return 0;
}

#define AUTH_ASSERT(cond, format, args...) do {\
	if (!(cond)) {\
		sc_do_log(card->ctx, SC_LOG_DEBUG_NORMAL, __FILE__, __LINE__, __FUNCTION__, format , ## args); \
		return SC_ERROR_SM;\
	}\
} while (0);

#define DECRYPT_ASSERT(cond, format, args...) do {\
	if (!(cond)) {\
		sc_do_log(card->ctx, SC_LOG_DEBUG_NORMAL, __FILE__, __LINE__, __FUNCTION__, format , ## args); \
		return SC_ERROR_SM;\
	}\
} while (0);

int sm_generic_receive_transform(sc_card_t *card, sc_apdu_t *orig_apdu,
	sc_apdu_t *transformed_apdu,
	const u8 *key, int enc_method, int sig_method)
{
	int r;
	static int turn = 0;

	if (!key) {
        sc_error(card->ctx, "SM key not provided, cannot continue");
        return SC_ERROR_INTERNAL;
	}

	SC_DEBUG5("Receiving, turn %d\n", turn++);

	orig_apdu->sw1 = transformed_apdu->sw1;
	orig_apdu->sw2 = transformed_apdu->sw2;
	orig_apdu->resplen = transformed_apdu->resplen;

	r = sc_check_sw(card, orig_apdu->sw1, orig_apdu->sw2);
	sc_error(card->ctx, "Got SW error in response to SM APDU (le=%d, resplen=%d)",
		transformed_apdu->le, transformed_apdu->resplen);

	/* Skip what follows if the response length is zero. */
	if (transformed_apdu->resplen == 0) {
		return 0;
	}

	/* Check envelope */
	int i = 0;
	u8 *resp_value, *resp_mac_value;
	size_t resp_value_len;

	if(enc_method) {
		DECRYPT_ASSERT(transformed_apdu->resp[i++] == 0x87, 
			"Invalid tag in SM encrypted response object");

		/* plaintext length = the ciphertext, w/o initial ciphertext padding,
		 * the single 0x01 byte. We'll remove and count plaintext end padding
		 * at the end of this process. */
		resp_value_len = transformed_apdu->resp[i++] -1;
		DECRYPT_ASSERT((resp_value_len % 8) == 0, "Response length not "
			"aligned with crypto block size");
		DECRYPT_ASSERT(transformed_apdu->resp[i++] == 0x01, "Invalid padding "
			"indicator in response ciphertext object");
	} else if (sig_method) {
		AUTH_ASSERT(transformed_apdu->resp[i++] == 0x81, "Invalid tag in SM "
			"cleartext response object");
		resp_value_len = transformed_apdu->resp[i++];
	} else {
		DECRYPT_ASSERT(0, "The generic SM receive transform has been called "
			"without signing nor encoding");
	}

	/* The counter 'i' has reached the response value */
	resp_value = &transformed_apdu->resp[i];

	if(card->ctx->debug >= 5) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Crypto APDU to interpret (w/o SW1, SW2):\n");
		sc_apdu_log(card->ctx, SC_LOG_DEBUG_NORMAL, &transformed_apdu->resp[i], resp_value_len, 0);
	}

	i += resp_value_len;

	DECRYPT_ASSERT(i<=transformed_apdu->resplen, "Truncated response");

	if(sig_method) {
		SC_DEBUG5("MAC object starts at %p with %x, %x\n",
			&transformed_apdu->resp[i] ,transformed_apdu->resp[i],
			transformed_apdu->resp[i+1]);
			
		AUTH_ASSERT(transformed_apdu->resp[i++] == 0x8e, "Invalid tag in "
			"SM_ENC_SIG MAC object");
		
		AUTH_ASSERT(transformed_apdu->resp[i++] == 0x08, "Invalid length of SM_ENC MAC object");

		resp_mac_value = &transformed_apdu->resp[i];
		
		SC_DEBUG5("MAC starts at %p with %x, %x\n",
			resp_mac_value, resp_mac_value[0], resp_mac_value[1]);
			
		AUTH_ASSERT(i <= transformed_apdu->resplen, "Truncated response "
			"(in MAC computation)");

		/* Compute MAC */
		u8 our_mac[8];
		size_t signable_len = resp_value_len+2;
		if(enc_method) signable_len++; /* for padding byte */
		SC_DEBUG5("Signable block starts with %x, %x, length %x\n",
			transformed_apdu->resp[0], transformed_apdu->resp[1], signable_len);
		r = compute_sm_signature(card, sig_method,
			our_mac, transformed_apdu->resp, signable_len,
			transformed_apdu, card->sm_ctx.info.session.cns.host_challenge, key);
		AUTH_ASSERT(r == 0, "Could not compute MAC on response");
		r = memcmp(resp_mac_value, our_mac, 8);
		AUTH_ASSERT(r == 0, "Received and computed MACs do not match");
	}

	if(!enc_method) {
		orig_apdu->resplen = resp_value_len;
		memcpy(orig_apdu->resp, resp_value, resp_value_len);
		return 0;
	} else if (enc_method) {
		struct {
			int useless;
			int pt_size;
			int useless2;
		} s;
		u8 pt_buf[SC_MAX_APDU_BUFFER_SIZE];
				
		r = do_3des(card, key, pt_buf, &s.pt_size, resp_value, resp_value_len, 0);
		DECRYPT_ASSERT(r == 0, "Could not decrypt SM response");

		orig_apdu->le = s.pt_size;
		DECRYPT_ASSERT(s.pt_size <= orig_apdu->resplen, "Response too long");

		memcpy(orig_apdu->resp, pt_buf, s.pt_size);
		
		orig_apdu->resplen = s.pt_size;
		
		if (card->ctx->debug >= 5) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unencrypted APDU:\n");
			sc_apdu_log(card->ctx, SC_LOG_DEBUG_NORMAL, orig_apdu->resp, orig_apdu->resplen, 0);
		}
		
		return 0;
	}

	sc_error(card->ctx, "Should have never arrived here\n");
	return SC_ERROR_INTERNAL;
}

static int
itacns_sm_get_wrapped_apdu(struct sc_card *card, struct sc_apdu *plain, struct sc_apdu **sm_apdu)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu *apdu = NULL;
	int rv  = 0;

	LOG_FUNC_CALLED(ctx);

        if (!plain || !sm_apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_log(ctx, "called; CLA:%X, INS:%X, P1:%X, P2:%X, data(%i) %p",
			plain->cla, plain->ins, plain->p1, plain->p2, plain->datalen, plain->data);
        *sm_apdu = NULL;

	if ((plain->cla & 0x04)
		|| (plain->cla==0x00 && plain->ins==0x84)
		|| (plain->cla==0x80 && plain->ins==0x86)
		)   {
		sc_log(ctx, "SM wrap is not applied for this APDU");
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_NOT_APPLIED);
	}

	if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_NOT_INITIALIZED);

        apdu = calloc(1, sizeof(struct sc_apdu));
        if (!apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy((void *)apdu, (void *)plain, sizeof(struct sc_apdu));

        apdu->data = calloc (1, plain->datalen + 24);
        if (!apdu->data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	if (plain->data && plain->datalen)
		memcpy((unsigned char *) apdu->data, plain->data, plain->datalen);

        apdu->resp = calloc (1, plain->resplen + 32);
        if (!apdu->resp)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	card->sm_ctx.info.cmd = SM_CMD_APDU_TRANSMIT;
	card->sm_ctx.info.cmd_data = (void *)apdu;

	rv = sm_generic_send_transform(card, plain, apdu, 
		&card->sm_ctx.info.session.cns.symmetric_key, 1, 1);
	LOG_TEST_RET(ctx, rv, "SM: GET_APDUS failed");

	*sm_apdu = apdu;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
itacns_sm_free_wrapped_apdu(struct sc_card *card, struct sc_apdu *plain, struct sc_apdu **sm_apdu)
{
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	if (!sm_apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
    if (!(*sm_apdu))
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

    if (plain)   {
    	int rv = sm_generic_receive_transform(card, plain, *sm_apdu,
    		card->sm_ctx.info.session.cns.symmetric_key, 1, 1);
    	if (rv)
    		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Receive transform failed");
	}

	if ((*sm_apdu)->data)
		free((unsigned char *) (*sm_apdu)->data);
	if ((*sm_apdu)->resp)
		free((unsigned char *) (*sm_apdu)->resp);

	free(*sm_apdu);
	*sm_apdu = NULL;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}



#endif

