/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_preallocated.h"
#include "ripemd160-wasm.c"
#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"
#include "ecmult_big.h"

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

#define ARG_CHECK_NO_RETURN(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        secp256k1_callback_call(&ctx->illegal_callback, #cond); \
    } \
} while(0)

#ifndef USE_EXTERNAL_DEFAULT_CALLBACKS
#include <stdlib.h>
#include <stdio.h>
static void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    abort();
}
static void secp256k1_default_error_callback_fn(const char* str, void* data) {
    (void)data;
    abort();
}
#else
void secp256k1_default_illegal_callback_fn(const char* str, void* data);
void secp256k1_default_error_callback_fn(const char* str, void* data);
#endif

static const secp256k1_callback default_illegal_callback = {
    secp256k1_default_illegal_callback_fn,
    NULL
};

static const secp256k1_callback default_error_callback = {
    secp256k1_default_error_callback_fn,
    NULL
};

struct secp256k1_context_struct {
    secp256k1_ecmult_context ecmult_ctx;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
};

static const secp256k1_context secp256k1_context_no_precomp_ = {
    { 0 },
    { 0 },
    { secp256k1_default_illegal_callback_fn, 0 },
    { secp256k1_default_error_callback_fn, 0 }
};
const secp256k1_context *secp256k1_context_no_precomp = &secp256k1_context_no_precomp_;

size_t secp256k1_context_preallocated_size(unsigned int flags) {
    size_t ret = ROUND_TO_ALIGN(sizeof(secp256k1_context));

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            secp256k1_callback_call(&default_illegal_callback,
                                    "Invalid flags");
            return 0;
    }

    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        ret += SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    }
    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        ret += SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
    }
    return ret;
}

size_t secp256k1_context_preallocated_clone_size(const secp256k1_context* ctx) {
    size_t ret = ROUND_TO_ALIGN(sizeof(secp256k1_context));
    VERIFY_CHECK(ctx != NULL);
    if (secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        ret += SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    }
    if (secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx)) {
        ret += SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
    }
    return ret;
}

secp256k1_context* secp256k1_context_preallocated_create(void* prealloc, unsigned int flags) {
    void* const base = prealloc;
    size_t prealloc_size;
    secp256k1_context* ret;

    VERIFY_CHECK(prealloc != NULL);
    prealloc_size = secp256k1_context_preallocated_size(flags);
    ret = (secp256k1_context*)manual_alloc(&prealloc, sizeof(secp256k1_context), base, prealloc_size);
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            secp256k1_callback_call(&ret->illegal_callback,
                                    "Invalid flags");
            return NULL;
    }

    secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &prealloc);
    }
    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        secp256k1_ecmult_context_build(&ret->ecmult_ctx, &prealloc);
    }

    return (secp256k1_context*) ret;
}

secp256k1_context* secp256k1_context_create(unsigned int flags) {
    size_t const prealloc_size = secp256k1_context_preallocated_size(flags);
    secp256k1_context* ctx = (secp256k1_context*)checked_malloc(&default_error_callback, prealloc_size);
    if (EXPECT(secp256k1_context_preallocated_create(ctx, flags) == NULL, 0)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

secp256k1_context* secp256k1_context_preallocated_clone(const secp256k1_context* ctx, void* prealloc) {
    size_t prealloc_size;
    secp256k1_context* ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(prealloc != NULL);

    prealloc_size = secp256k1_context_preallocated_clone_size(ctx);
    ret = (secp256k1_context*)prealloc;
    memcpy(ret, ctx, prealloc_size);
    secp256k1_ecmult_gen_context_finalize_memcpy(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx);
    secp256k1_ecmult_context_finalize_memcpy(&ret->ecmult_ctx, &ctx->ecmult_ctx);
    return ret;
}

secp256k1_context* secp256k1_context_clone(const secp256k1_context* ctx) {
    secp256k1_context* ret;
    size_t prealloc_size;

    VERIFY_CHECK(ctx != NULL);
    prealloc_size = secp256k1_context_preallocated_clone_size(ctx);
    ret = (secp256k1_context*)checked_malloc(&ctx->error_callback, prealloc_size);
    ret = secp256k1_context_preallocated_clone(ctx, ret);
    return ret;
}

void secp256k1_context_preallocated_destroy(secp256k1_context* ctx) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (ctx != NULL) {
        secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);
    }
}

void secp256k1_context_destroy(secp256k1_context* ctx) {
    if (ctx != NULL) {
        secp256k1_context_preallocated_destroy(ctx);
        free(ctx);
    }
}

void secp256k1_context_set_illegal_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = secp256k1_default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void secp256k1_context_set_error_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = secp256k1_default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

secp256k1_scratch_space* secp256k1_scratch_space_create(const secp256k1_context* ctx, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    return secp256k1_scratch_create(&ctx->error_callback, max_size);
}

void secp256k1_scratch_space_destroy(const secp256k1_context *ctx, secp256k1_scratch_space* scratch) {
    VERIFY_CHECK(ctx != NULL);
    secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}

int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & SECP256K1_FLAGS_BIT_COMPRESSION) ? 33 : 65));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void secp256k1_ecdsa_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void secp256k1_ecdsa_signature_save(secp256k1_ecdsa_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int secp256k1_ecdsa_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int secp256k1_ecdsa_signature_malleate(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);
    ARG_CHECK(sigout != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(sigout, &r, &s);

    return 1;
}

int secp256k1_ecdsa_signature_normalize(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin) {
    secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            secp256k1_scalar_negate(&s, &s);
        }
        secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!secp256k1_scalar_is_high(&s) &&
            secp256k1_pubkey_load(ctx, &q, pubkey) &&
            secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
}

static SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const secp256k1_nonce_function secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const secp256k1_nonce_function secp256k1_nonce_function_default = nonce_function_rfc6979;

int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    secp256k1_scalar sec, non, msg;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !secp256k1_scalar_is_zero(&non)) {
                if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        secp256k1_scalar_clear(&msg);
        secp256k1_scalar_clear(&non);
        secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
    secp256k1_scalar sec;
    int ret;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !secp256k1_scalar_is_zero(&sec);
    if (ret) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &sec);
        secp256k1_ge_set_gej(&p, &pj);
        secp256k1_pubkey_save(pubkey, &p);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_privkey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
    secp256k1_scalar sec;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    secp256k1_scalar_negate(&sec, &sec);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&sec);
    return 1;
}

int secp256k1_ec_pubkey_negate(const secp256k1_context* ctx, secp256k1_pubkey *pubkey) {
    int ret = 0;
    secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        secp256k1_ge_neg(&p, &p);
        secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}

int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar term;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&term);
    return ret;
}

int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar term;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &p, &term)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar factor;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ret = !overflow && secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&factor);
    return ret;
}

int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    if (secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    }
    return 1;
}

int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    secp256k1_gej Qj;
    secp256k1_ge Q;

    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}


int secp256k1_ec_pubkey_pub_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkeyone, const secp256k1_pubkey *pubkeytwo) {
    secp256k1_gej Qj;
    secp256k1_ge Q;
    secp256k1_ge Q2;

    ARG_CHECK(pubkeyone != NULL);
    ARG_CHECK(pubkeytwo != NULL);
    secp256k1_gej_set_infinity(&Qj);
    secp256k1_pubkey_load(ctx, &Q, pubkeyone);
    memset(pubkeyone, 0, sizeof(*pubkeyone));
    secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    secp256k1_pubkey_load(ctx, &Q2, pubkeytwo);
    secp256k1_gej_add_ge(&Qj, &Qj, &Q2);
        
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubkeyone, &Q);
    return 1;
}

/* size_t key_count = 1;
secp256k1_gej* maingej;
secp256k1_fe *fe_in;
secp256k1_fe *fe_out; */


struct bdemo {
    /* Maximum number of elements this scratch space can hold. */
    const size_t size;

    /* Output from individual secp256k1_ecmult_gen. */
    secp256k1_gej *gej;

    /* Input and output buffers for secp256k1_fe_inv_all_var. */
    secp256k1_fe  *fe_in;
    secp256k1_fe  *fe_out;
};


bigole_scratch* demo_create(const secp256k1_context* ctx, const size_t size) {
    bigole_scratch* rtn = (bigole_scratch *)checked_malloc(&ctx->error_callback, sizeof(bigole_scratch));

    /* Cast away const-ness to set the size value.  */
    /* http://stackoverflow.com/a/9691556/477563    */
    *(size_t *)&rtn->size = size;

    rtn->gej    = (secp256k1_gej*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * size);
    rtn->fe_in  = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);
    rtn->fe_out = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);

    return rtn;
}
/** Create a secp256k1 ecmult big context.
 *
 *  Returns: a newly created ecmult big context.
 *  Args:   ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  In:     bits:   the window size in bits for the precomputation table
 */
secp256k1_ecmult_big_context* secp256k1_ecmult_big_create(const secp256k1_context* ctx, const unsigned int bits) {
    unsigned int windows;
    size_t window_size, total_size;
    size_t i, row;

    secp256k1_fe  fe_zinv;
    secp256k1_ge  ge_temp;
    secp256k1_ge  ge_window_one = secp256k1_ge_const_g;
    secp256k1_gej gej_window_base;
    secp256k1_ecmult_big_context *rtn;


    /* No point using fewer bits than the default implementation. */
    ARG_CHECK(bits >=  4);

    /* Each signed digit result must fit in a int64_t, we can't be larger.      */
    /* We also possibly subtract (1 << bits) and can't shift into the sign bit. */
    ARG_CHECK(bits <= 62);

    /* We +1 to account for a possible high 1 bit after converting the privkey to signed digit form.    */
    /* This means our table reaches to 257 bits even though the privkey scalar is at most 256 bits.     */
    windows = (256 / bits) + 1;
    window_size = (1 << (bits - 1));

    /* Total number of required point storage elements.                                 */
    /* This differs from the (windows * window_size) because the last row can be shrunk */
    /*   as it only needs to extend enough to include a possible 1 in the 257th bit.    */
    total_size = (256 / bits) * window_size + (1 << (256 % bits));



    /**************** Allocate Struct Members *****************/
    rtn = (secp256k1_ecmult_big_context *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ecmult_big_context));
    *(unsigned int *)(&rtn->bits) = bits;
    *(unsigned int *)(&rtn->windows) = windows;

    /* An array of secp256k1_ge_storage pointers, one for each window. */
    rtn->precomp = (secp256k1_ge_storage **)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage *) * windows);

    /* Bulk allocate up front.  We'd rather run out of memory now than during computation.  */
    /* Only the 0th row is malloc'd, the rest will be updated to point to row starts        */
    /*   within the giant chunk of memory that we've allocated.                             */
    rtn->precomp[0] = (secp256k1_ge_storage *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage) * total_size);

    /* Each row starts window_size elements after the previous. */
    for ( i = 1; i < windows; i++ ) { rtn->precomp[i] = (rtn->precomp[i - 1] + window_size); }

    rtn->gej_temp = (secp256k1_gej *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * window_size);
    rtn->z_ratio  = (secp256k1_fe  *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * window_size);



    /************ Precomputed Table Initialization ************/
    secp256k1_gej_set_ge(&gej_window_base, &ge_window_one);

    /* This is the same for all windows.    */
    secp256k1_fe_set_int(&(rtn->z_ratio[0]), 0);


    for ( row = 0; row < windows; row++ ) {
        /* The last row is a bit smaller, only extending to include the 257th bit. */
        window_size = ( row == windows - 1 ? (1 << (256 % bits)) : (1 << (bits - 1)) );

        /* The base element of each row is 2^bits times the previous row's base. */
        if ( row > 0 ) {
            for ( i = 0; i < bits; i++ ) { secp256k1_gej_double_var(&gej_window_base, &gej_window_base, NULL); }
        }
        rtn->gej_temp[0] = gej_window_base;

        /* The base element is also our "one" value for this row.   */
        /* If we are at offset 2^X, adding "one" should add 2^X.    */
        secp256k1_ge_set_gej(&ge_window_one, &gej_window_base);


        /* Repeated + 1s to fill the rest of the row.   */

        /* We capture the Z ratios between consecutive points for quick Z inversion.    */
        /*   gej_temp[i-1].z * z_ratio[i] => gej_temp[i].z                              */
        /* This means that z_ratio[i] = (gej_temp[i-1].z)^-1 * gej_temp[i].z            */
        /* If we know gej_temp[i].z^-1, we can get gej_temp[i-1].z^1 using z_ratio[i]   */
        /* Visually:                                    */
        /* i            0           1           2       */
        /* gej_temp     a           b           c       */
        /* z_ratio     NaN      (a^-1)*b    (b^-1)*c    */
        for ( i = 1; i < window_size; i++ ) {
            secp256k1_gej_add_ge_var(&(rtn->gej_temp[i]), &(rtn->gej_temp[i-1]), &ge_window_one, &(rtn->z_ratio[i]));
        }


        /* An unpacked version of secp256k1_ge_set_table_gej_var() that works   */
        /*   element by element instead of requiring a secp256k1_ge *buffer.    */

        /* Invert the last Z coordinate manually.   */
        i = window_size - 1;
        secp256k1_fe_inv(&fe_zinv, &(rtn->gej_temp[i].z));
        secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i]), &fe_zinv);
        secp256k1_ge_to_storage(&(rtn->precomp[row][i]), &ge_temp);

        /* Use the last element's known Z inverse to determine the previous' Z inverse. */
        for ( ; i > 0; i-- ) {
            /* fe_zinv = (gej_temp[i].z)^-1                 */
            /* (gej_temp[i-1].z)^-1 = z_ratio[i] * fe_zinv  */
            secp256k1_fe_mul(&fe_zinv, &fe_zinv, &(rtn->z_ratio[i]));
            /* fe_zinv = (gej_temp[i-1].z)^-1               */

            secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i-1]), &fe_zinv);
            secp256k1_ge_to_storage(&(rtn->precomp[row][i-1]), &ge_temp);
        }
    }


    /* We won't be using these any more.    */
    free(rtn->gej_temp); rtn->gej_temp = NULL;
    free(rtn->z_ratio);  rtn->z_ratio  = NULL;

    return rtn;
}


/** Destroy a secp256k1 ecmult big context.
 *
 *  The context pointer may not be used afterwards.
 *  Args:   bmul:   an existing context to destroy (cannot be NULL)
 */
void secp256k1_ecmult_big_destroy(secp256k1_ecmult_big_context* bmul) {
    VERIFY_CHECK(bmul != NULL);
    if ( bmul == NULL ) { return; }

    /* Just in case the caller tries to use after free. */
    *(unsigned int *)(&bmul->bits)    = 0;
    *(unsigned int *)(&bmul->windows) = 0;

    if ( bmul->precomp != NULL ) {
        /* This was allocated with a single malloc, it will be freed with a single free. */
        if ( bmul->precomp[0] != NULL ) { free(bmul->precomp[0]); bmul->precomp[0] = NULL; }

        free(bmul->precomp); bmul->precomp = NULL;
    }

    /* These should already be freed, but just in case. */
    if ( bmul->gej_temp != NULL ) { free(bmul->gej_temp); bmul->gej_temp = NULL; }
    if ( bmul->z_ratio  != NULL ) { free(bmul->z_ratio ); bmul->z_ratio  = NULL; }

    free(bmul);
}



/** Shifts and returns the first N <= 64 bits from a scalar.
 *  The default secp256k1_scalar_shr_int only handles up to 15 bits.
 *
 *  Args:   s:      a scalar object to shift from (cannot be NULL)
 *  In:     n:      number of bits to shift off and return
 */
uint64_t secp256k1_scalar_shr_any(secp256k1_scalar *s, unsigned int n) {
    unsigned int cur_shift = 0, offset = 0;
    uint64_t rtn = 0;

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(n >   0);
    VERIFY_CHECK(n <= 64);

    while ( n > 0 ) {
        /* Shift up to 15 bits at a time, or N bits, whichever is smaller.  */
        /* secp256k1_scalar_shr_int() is hard limited to (0 < n < 16).      */
        cur_shift = ( n > 15 ? 15 : n );

        rtn |= ((uint64_t)secp256k1_scalar_shr_int(s, cur_shift) << (uint64_t)offset);

        offset += cur_shift;
        n      -= cur_shift;
    }

    return rtn;
}


/** Converts the lowest w-bit window of scalar s into signed binary form
 *
 *  Returns: signed form of the lowest w-bit window
 *  Args:   s:  scalar to read from and modified (cannot be NULL)
 *  In:     w:  window size in bits (w < 64)
 */
static int64_t secp256k1_scalar_sdigit_single(secp256k1_scalar *s, unsigned int w) {
    int64_t sdigit = 0;

    /* Represents a 1 bit in the next window's least significant bit.       */
    /* VERIFY_CHECK verifies that (1 << w) won't touch int64_t's sign bit.  */
    int64_t overflow_bit = (int64_t)(1 << w);

    /* Represents the maximum positive value in a w-bit precomp table.  */
    /* Values greater than this are converted to negative values and    */
    /*   will "reverse borrow" a bit from the next window.              */
    int64_t precomp_max = (int64_t)(1 << (w-1));

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(w >=  1);
    VERIFY_CHECK(w <= 62);

    sdigit = (int64_t)secp256k1_scalar_shr_any(s, w);

    if ( sdigit <= precomp_max ) {
        /* A w-bit precomp table has this digit as a positive value, return as-is.  */
        return sdigit;

    } else {
        secp256k1_scalar one;
        secp256k1_scalar_set_int(&one, 1);

        /* Convert this digit to a negative value, but balance s by adding it's value.  */
        /* Subtracting our sdigit value carries over into a 1 bit of the next digit.    */
        /* Since s has been shifted down w bits, s += 1 does the same thing.            */
        sdigit -= overflow_bit;

        secp256k1_scalar_add(s, s, &one);

        return sdigit;
    }
}


/** Converts s to a signed digit form using w-bit windows.
 *
 *  Returns: number of signed digits written, some digits may be zero
 *  Out:    sdigits:    signed digit representation of s (cannot be NULL)
 *  In:     s:          scalar value to convert to signed digit form
 *          w:          window size in bits
 */
static size_t secp256k1_scalar_sdigit(int64_t *sdigits, secp256k1_scalar s, unsigned int w) {
    size_t digits = 0;

    VERIFY_CHECK(sdigits != NULL);
    VERIFY_CHECK(w >=  1);
    VERIFY_CHECK(w <= 62);

    while ( !secp256k1_scalar_is_zero(&s) ) {
        sdigits[digits] = secp256k1_scalar_sdigit_single(&s, w);
        digits++;
    }

    return digits;
}



/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
static void secp256k1_ecmult_big(const secp256k1_ecmult_big_context* bmul, secp256k1_gej *r, const secp256k1_scalar *a) {
    size_t  window = 0;
    int64_t sdigit = 0;
    secp256k1_ge window_value;

    /* Copy of the input scalar which secp256k1_scalar_sdigit_single will destroy. */
    secp256k1_scalar privkey = *a;

    VERIFY_CHECK(bmul != NULL);
    VERIFY_CHECK(bmul->bits > 0);
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);

    /* Until we hit a non-zero window, the value of r is undefined. */
    secp256k1_gej_set_infinity(r);

    /* If the privkey is zero, bail. */
    if ( secp256k1_scalar_is_zero(&privkey) ) { return; }


    /* Incrementally convert the privkey into signed digit form, one window at a time. */
    while ( window < bmul->windows && !secp256k1_scalar_is_zero(&privkey) ) {
        sdigit = secp256k1_scalar_sdigit_single(&privkey, bmul->bits);

        /* Zero windows have no representation in our precomputed table. */
        if ( sdigit != 0 ) {
            if ( sdigit < 0 ) {
                /* Use the positive precomp index and negate the result. */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ -(sdigit) - 1 ]));
                secp256k1_ge_neg(&window_value, &window_value);
            } else {
                /* Use the precomp index and result as-is.  */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ +(sdigit) - 1 ]));
            }

            /* The first addition is automatically replaced by a load when r = inf. */
            secp256k1_gej_add_ge_var(r, r, &window_value, NULL);
        }

        window++;
    }

    /* If privkey isn't zero, something broke.  */
    VERIFY_CHECK(secp256k1_scalar_is_zero(&privkey));
}


size_t key_count = 0;
bigole_scratch *scr;

const unsigned char sp_one_G1[65] = {
    4, 121, 190, 102, 126, 249, 220, 187, 172,  85, 160,
   98, 149, 206, 135,  11,   7,   2, 155, 252, 219,  45,
  206,  40, 217,  89, 242, 129,  91,  22, 248,  23, 152,
   72,  58, 218, 119,  38, 163, 196, 101,  93, 164, 251,
  252,  14,  17,   8, 168, 253,  23, 180,  72, 166, 133,
   84,  25, 156,  71, 208, 143, 251,  16, 212, 184
};
int secp256k1_ec_pubkey_pub_add_batch(const secp256k1_context* ctx, unsigned char *pubkeys, const secp256k1_pubkey *pubkeyone, const secp256k1_pubkey *pubkeytwo) {
    secp256k1_gej Qj;
    secp256k1_ge Q;
    secp256k1_ge Q2;
    secp256k1_ge ge_pubkey;
    secp256k1_ge ge_emp;
    secp256k1_pubkey sd;
    secp256k1_scalar s_p;
    unsigned char sha_bin[32];
    unsigned char pub_bin[33];
    unsigned char ripemd_bin[20];
    unsigned char ripemd_search[20];
    memcpy(ripemd_search,  pubkeytwo,  20);
    secp256k1_sha256 lasher;
    if(1>key_count){
        /* printf("erde\n"); */
        key_count = 1000000;
        scr = demo_create(ctx, key_count);
    }
    size_t i, dummy, out_keys,c;
    size_t pubkey_size = 65;
    memset(pubkeys, 0, sizeof(*pubkeys) * 32 * 1);
/* for (int i = 0; i < 20; i++) {
    printf("%02X", ripemd_search[i]);
} */
    secp256k1_gej_set_infinity(&Qj);
    secp256k1_ge_set_infinity(&ge_emp);
    secp256k1_pubkey_load(ctx, &Q, pubkeyone);
    secp256k1_gej_add_ge(&(scr->gej[0]), &Qj, &Q);
    secp256k1_ec_pubkey_parse(ctx, &sd, sp_one_G1,65);
    secp256k1_pubkey_load(ctx, &Q2, &sd);
    out_keys = 0;
    scr->fe_in[out_keys] = scr->gej[0].z;
    Qj = scr->gej[0];
    out_keys++;
    int ret;
    int xret=0;
    for ( i = 1; i < key_count; i++ ) {
        secp256k1_gej_add_ge(&(scr->gej[i]), &Qj, &Q2);
        scr->fe_in[out_keys] = scr->gej[i].z;
        Qj = scr->gej[i];
        out_keys++;
        
    }
    /* printf("borlo\n"); */
    if ( out_keys > 0 ) {
        /* Invert all Jacobian public keys' Z values in one go. */
        secp256k1_fe_inv_all_var(scr->fe_out, scr->fe_in, out_keys);
    }
    out_keys = 0;
    /* printf("korlo\n"); */
    for ( i = 0; i < key_count; i++) {
        secp256k1_ge_set_gej_zinv(&ge_pubkey, &(scr->gej[i]), &(scr->fe_out[out_keys]));

        /* Serialize the public key into the requested format. 0 uncom*/
        secp256k1_eckey_pubkey_serialize(&ge_pubkey, &pub_bin, &dummy, 1);

        out_keys++;

    }
    return 1;
}

size_t key_count2 = 0;
bigole_scratch *scr2;
secp256k1_ecmult_big_context* bmul;
int secp256k1_ec_mul_batch(const secp256k1_context* ctx, unsigned char *pubkeys, const unsigned char *privkeys) {
    secp256k1_scalar s_privkey;
    secp256k1_ge ge_pubkey;
    /* Argument checking. */
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    if(1>key_count2){
        /* printf("erde\n"); key_count*/
        key_count2 = 10000;
        scr2 = demo_create(ctx, key_count2);
        bmul = secp256k1_ecmult_big_create(ctx, 16);
    }
    size_t i, dummy, out_keys;
    size_t pubkey_size = 65;
    memset(pubkeys, 0, sizeof(*pubkeys) * pubkey_size * key_count2);
    out_keys = 0;
    for ( i = 0; i < key_count2; i++ ) {
        secp256k1_scalar_set_b32(&s_privkey, &(privkeys[32 * i]), NULL);
        
        /* secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &(scr2->gej[i]), &s_privkey); */
        secp256k1_ecmult_big(bmul, &(scr2->gej[i]), &s_privkey);
        scr2->fe_in[out_keys] = scr2->gej[i].z;
        
        out_keys++;
        
    }
    
    if ( out_keys > 0 ) {
        /* Invert all Jacobian public keys' Z values in one go. */
        secp256k1_fe_inv_all_var(scr2->fe_out, scr2->fe_in, out_keys);
    }
    out_keys = 0;
    
    for ( i = 0; i < key_count2; i++) {
        secp256k1_ge_set_gej_zinv(&ge_pubkey, &(scr2->gej[i]), &(scr2->fe_out[out_keys]));

        /* Serialize the public key into the requested format. 0 uncom*/
        secp256k1_eckey_pubkey_serialize(&ge_pubkey, &(pubkeys[pubkey_size * i]), &dummy, 0);
        out_keys++;
    }
    return 1;
}
#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORR
# include "modules/schnorr/main_impl.h"
#endif
