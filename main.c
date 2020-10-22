// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <err.h>
#include <tee_client_api.h>
#include <ta_se050_cert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#define PEM_CERT "/tmp/cert.pem"
#define DER_CERT "/tmp/cert.der"

static const struct {
	const char *import_cert;
	const char *import_keyp;
	const char *der2pem;
	const char *rm_der;
	const char *rm_pem;
} cmd = {
	.rm_der = "rm "DER_CERT,
	.rm_pem = "rm "PEM_CERT,
	.der2pem = "openssl x509 -inform der -in " DER_CERT " -out " PEM_CERT,
	.import_cert = "pkcs11-tool --module /usr/lib/libsks.so.0.0 -l "
	"--type cert --pin %s --id %s --write-object " DER_CERT,
	.import_keyp = "pkcs11-tool --module /usr/lib/libsks.so.0.0 "
	"--key-type %s --pin %s --id %s --label SE_%x --token-label %s "
	"--keypairgen "
};

struct cert_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

static void prepare_tee_session(struct cert_ctx *ctx)
{
	TEEC_UUID uuid = PTA_SE050_CERT_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, origin);
}

static void terminate_tee_session(struct cert_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static int do_certificate(uint32_t nxp, char *id, char *pin)
{
	char buffer[2048] = { 0 };
	char *import_cert = buffer;
	struct cert_ctx ctx;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin;
	FILE *file;
	size_t len;

	prepare_tee_session(&ctx);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INOUT,
					 TEEC_NONE,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = buffer;
	op.params[0].tmpref.size = sizeof(buffer);
	op.params[1].value.a = sizeof(buffer);
	op.params[1].value.b = nxp;
	res = TEEC_InvokeCommand(&ctx.sess, PTA_CMD_SE050_CERT_GET,
				 &op, &origin);
	terminate_tee_session(&ctx);
	if (res)
		return -1;

	file = fopen(DER_CERT, "w");
	if (!file)
		return -EINVAL;

	len = fwrite(buffer, 1, op.params[1].value.a, file);
	fclose(file);
	if (len != op.params[1].value.a)
		return -EIO;

	memset(buffer, '\0', sizeof(buffer));

	sprintf(import_cert, cmd.import_cert, pin, id);
	system(import_cert);
	system(cmd.rm_der);

	return 0;
}

static int do_keypairgen(uint32_t k, char *id, char *pin, char *token, char *t)
{
	char import_keyp[2048] = { '\0' };

	sprintf(import_keyp, cmd.import_keyp, t, pin, id, k, token);
	system(import_keyp);

	return 0;
}

static const struct option options[] = {
	{
#define help_opt 0
		.name = "help",
		.has_arg = 0,
		.flag = NULL,
	},
	{
#define cert_opt 1
		.name = "cert",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define keyp_opt 2
		.name = "keyp",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_id_opt 3
		.name = "id",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_pin_opt 4
		.name = "pin",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_type_opt 5
		.name = "key-type",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_token_opt 6
		.name = "token-label",
		.has_arg = 1,
		.flag = NULL,
	},
	{
		.name = NULL,
	},
};

static void usage(void)
{
	fprintf(stderr, "This tool imports certficates and keys from the NXP SE050 into the cryptoki\n");
	fprintf(stderr, "Example: \n"
			"key import:         pkcs11-se050-import --keyp 0xf0000110 --id 12 --pin 87654321 --token-label aktualizr --key-type RSA:2048\n"
			"certificate import: pkcs11-se050-import --cert 0xf0000123 --id 45 --pin 87654321\n\n");
	fprintf(stderr, "Usage: with:\n");
	fprintf(stderr, "--help             Display this menu\n");
	fprintf(stderr, "--cert=<nxp id>    Import a Certificate to pkcs11"
			"(requires pin and id)\n");
	fprintf(stderr, "--keyp=<nxp_id>    Import a Keypair to pkcs11"
			"(requires pin, id, token-label and key-type)\n");
	fprintf(stderr, "--token-label\n");
	fprintf(stderr, "--key-type\n");
	fprintf(stderr, "--pin\n");
	fprintf(stderr, "--id");
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	char *sks_pin, *sks_id, *sks_token, *sks_type, *nxp_id;
	bool do_cert = false, do_keyp = false;
	int lindex, opt;

	for (;;) {
		lindex = -1;
		opt = getopt_long_only(argc, argv, "", options, &lindex);
		if (opt == EOF)
			break;

		switch (lindex) {
		case help_opt:
			usage();
			exit(0);
		case cert_opt:
			do_cert = true;
			nxp_id = optarg;
			break;
		case keyp_opt:
			do_keyp = true;
			nxp_id = optarg;
			break;
		case sks_id_opt:
			sks_id = optarg;
			break;
		case sks_pin_opt:
			sks_pin = optarg;
			break;
		case sks_type_opt:
			sks_type = optarg;
			break;
		case sks_token_opt:
			sks_token = optarg;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (do_cert && sks_id && sks_pin && nxp_id)
		return do_certificate(strtoul(nxp_id, NULL, 16),
				      sks_id, sks_pin);

	if (do_keyp && sks_id && sks_pin && sks_token && sks_type && nxp_id)
		return do_keypairgen(strtoul(nxp_id, NULL, 16),
				     sks_id, sks_pin, sks_token, sks_type);
	usage();
	exit(1);
}
