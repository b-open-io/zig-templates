/*
 * zig_templates — C ABI for the zig-templates Zig library.
 * Link against libzig_templates_c.a produced by `zig build`.
 *
 * All functions return 0 on success, negative on failure:
 *   -1  ERR_INVALID_INPUT
 *   -2  ERR_CRYPTO
 *   -3  ERR_BUFFER_TOO_SMALL
 *   -4  ERR_ALLOC
 */

#ifndef ZIG_TEMPLATES_H
#define ZIG_TEMPLATES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Inscription ───────────────────────────────────────────────────── */

/* Create an inscription envelope script.
 * content + content_len: raw inscription content bytes.
 * content_type + ct_len: MIME type string (e.g. "text/plain").
 * prefix + prefix_len: optional script prefix (pass NULL/0 for none).
 * out_script: caller-allocated buffer. out_script_len receives actual length. */
int zt_inscription_create(const unsigned char *content, size_t content_len,
                           const char *content_type, size_t ct_len,
                           const unsigned char *prefix, size_t prefix_len,
                           unsigned char *out_script, size_t *out_script_len);

/* ── MAP (Magic Attribute Protocol) ────────────────────────────────── */

/* Encode a MAP protocol script.
 * operation + op_len: "SET" or "DEL".
 * pairs_json + pairs_json_len: JSON array of [key, value] pairs,
 *   e.g. [["app","bsocial"],["type","post"]].
 * out_script: caller-allocated buffer. out_script_len receives actual length. */
int zt_map_encode(const char *operation, size_t op_len,
                   const char *pairs_json, size_t pairs_json_len,
                   unsigned char *out_script, size_t *out_script_len);

/* ── AIP (Author Identity Protocol) ───────────────────────────────── */

/* Sign data with AIP and return the full script (data + pipe + AIP fields).
 * privkey: 32-byte private key.
 * data + data_len: script bytes to sign (everything before the pipe).
 * out_script: caller-allocated buffer. out_script_len receives actual length. */
int zt_aip_sign(const unsigned char *privkey,
                 const unsigned char *data, size_t data_len,
                 unsigned char *out_script, size_t *out_script_len);

/* ── Lock (CLTV timelock) ─────────────────────────────────────────── */

/* Create a CLTV timelock locking script.
 * pubkey_hash: 20-byte HASH160 of the public key.
 * block_height: block height after which the output becomes spendable.
 * out_script: caller-allocated buffer. out_script_len receives actual length. */
int zt_lock_create(const unsigned char *pubkey_hash,
                    uint32_t block_height,
                    unsigned char *out_script, size_t *out_script_len);

/* ── OrdLock (marketplace listing) ────────────────────────────────── */

/* Create an OrdLock locking script for NFT marketplace listings.
 * seller_pkh: 20-byte public key hash of seller (cancel address).
 * pay_pkh: 20-byte public key hash of payment destination.
 * price_sats: listing price in satoshis.
 * out_script: caller-allocated buffer. out_script_len receives actual length. */
int zt_ordlock_create(const unsigned char *seller_pkh,
                       const unsigned char *pay_pkh,
                       uint64_t price_sats,
                       unsigned char *out_script, size_t *out_script_len);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_TEMPLATES_H */
