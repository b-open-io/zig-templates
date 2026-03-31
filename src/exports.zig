//! C ABI exports for zig-templates — allows linking libzig_templates_c.a into C/C++ projects.
//! All functions return 0 on success, negative on failure.
//! Allocations use page_allocator since callers cannot provide a Zig allocator.

const std = @import("std");
const bsvz = @import("bsvz");
const templates = @import("zig-templates");
const inscription = templates.inscription;
const map = templates.bitcom.map;
const aip = templates.bitcom.aip;
const lock_template = templates.lock;
const ordlock = templates.ordlock;

const alloc = std.heap.page_allocator;

// Error codes
const OK: c_int = 0;
const ERR_INVALID_INPUT: c_int = -1;
const ERR_CRYPTO: c_int = -2;
const ERR_BUFFER_TOO_SMALL: c_int = -3;
const ERR_ALLOC: c_int = -4;

fn copyToOut(src: []const u8, out_buf: [*c]u8, out_len: *usize) c_int {
    @memcpy(out_buf[0..src.len], src);
    out_len.* = src.len;
    return OK;
}

// ── Inscription ────────────────────────────────────────────────────────

/// Create an inscription envelope script.
///
/// content + content_len: raw inscription content bytes.
/// content_type + ct_len: MIME type string (e.g. "text/plain").
/// prefix + prefix_len: optional P2PKH or other script prefix (pass null/0 for none).
/// out_script must be pre-allocated by the caller.
/// out_script_len is set to the actual script length on success.
export fn zt_inscription_create(
    content: [*c]const u8,
    content_len: usize,
    content_type: [*c]const u8,
    ct_len: usize,
    prefix_ptr: [*c]const u8,
    prefix_len: usize,
    out_script: [*c]u8,
    out_script_len: *usize,
) c_int {
    if (content_len == 0 or ct_len == 0) return ERR_INVALID_INPUT;

    const content_slice = content[0..content_len];
    const ct_slice = content_type[0..ct_len];
    const script_prefix: ?[]const u8 = if (prefix_len > 0) prefix_ptr[0..prefix_len] else null;

    const script = inscription.create(alloc, content_slice, ct_slice, .{
        .script_prefix = script_prefix,
    }) catch return ERR_ALLOC;
    defer alloc.free(script);

    return copyToOut(script, out_script, out_script_len);
}

// ── MAP ────────────────────────────────────────────────────────────────

/// Encode a MAP protocol script.
///
/// operation: "SET" or "DEL" (null-terminated or with length).
/// pairs_json + pairs_json_len: JSON array of [key, value] pairs,
///   e.g. `[["app","bsocial"],["type","post"]]`.
/// out_script must be pre-allocated by the caller.
/// out_script_len is set to the actual script length on success.
export fn zt_map_encode(
    operation: [*c]const u8,
    op_len: usize,
    pairs_json: [*c]const u8,
    pairs_json_len: usize,
    out_script: [*c]u8,
    out_script_len: *usize,
) c_int {
    if (op_len == 0 or pairs_json_len == 0) return ERR_INVALID_INPUT;

    const op_str = operation[0..op_len];
    const op = map.Operation.fromString(op_str) orelse return ERR_INVALID_INPUT;

    const json_str = pairs_json[0..pairs_json_len];

    // Parse JSON array of [key, value] pairs
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, json_str, .{}) catch return ERR_INVALID_INPUT;
    defer parsed.deinit();

    if (parsed.value != .array) return ERR_INVALID_INPUT;
    const arr = parsed.value.array.items;

    // Convert JSON pairs to MAP Pair structs
    var pairs_buf = alloc.alloc(map.Pair, arr.len) catch return ERR_ALLOC;
    defer alloc.free(pairs_buf);

    for (arr, 0..) |item, i| {
        if (item != .array) return ERR_INVALID_INPUT;
        const pair_arr = item.array.items;
        if (pair_arr.len < 1) return ERR_INVALID_INPUT;
        if (pair_arr[0] != .string) return ERR_INVALID_INPUT;

        const key = pair_arr[0].string;
        const value: []const u8 = if (pair_arr.len >= 2 and pair_arr[1] == .string)
            pair_arr[1].string
        else
            "";

        pairs_buf[i] = .{ .key = key, .value = value };
    }

    const script = map.encode(alloc, op, pairs_buf) catch return ERR_ALLOC;
    defer alloc.free(script);

    return copyToOut(script, out_script, out_script_len);
}

// ── AIP ────────────────────────────────────────────────────────────────

/// Sign data with AIP (Author Identity Protocol) and return the full script
/// with pipe separator, AIP prefix, algorithm, address, and signature.
///
/// privkey: 32-byte private key.
/// data + data_len: the script bytes to sign (everything before the pipe).
/// out_script must be pre-allocated by the caller.
/// out_script_len is set to the actual script length on success.
export fn zt_aip_sign(
    privkey: [*c]const u8,
    data: [*c]const u8,
    data_len: usize,
    out_script: [*c]u8,
    out_script_len: *usize,
) c_int {
    if (data_len == 0) return ERR_INVALID_INPUT;

    const pk = bsvz.crypto.PrivateKey.fromBytes(privkey[0..32].*) catch return ERR_CRYPTO;
    const data_slice = data[0..data_len];

    const script = aip.appendToScript(alloc, data_slice, pk) catch return ERR_CRYPTO;
    defer alloc.free(script);

    return copyToOut(script, out_script, out_script_len);
}

// ── Lock (CLTV) ────────────────────────────────────────────────────────

/// Create a CLTV timelock locking script.
///
/// pubkey_hash: 20-byte HASH160 of the public key.
/// block_height: block height after which the output becomes spendable.
/// out_script must be pre-allocated by the caller.
/// out_script_len is set to the actual script length on success.
export fn zt_lock_create(
    pubkey_hash: [*c]const u8,
    block_height: u32,
    out_script: [*c]u8,
    out_script_len: *usize,
) c_int {
    const pkh: *const [20]u8 = @ptrCast(pubkey_hash[0..20]);

    const script = lock_template.lock(alloc, pkh, block_height) catch return ERR_ALLOC;
    defer alloc.free(script);

    return copyToOut(script, out_script, out_script_len);
}

// ── OrdLock ────────────────────────────────────────────────────────────

/// Create an OrdLock (marketplace listing) locking script.
///
/// seller_pkh: 20-byte public key hash of the seller (cancel address).
/// pay_pkh: 20-byte public key hash of the payment destination.
/// price_sats: listing price in satoshis.
/// out_script must be pre-allocated by the caller.
/// out_script_len is set to the actual script length on success.
export fn zt_ordlock_create(
    seller_pkh: [*c]const u8,
    pay_pkh: [*c]const u8,
    price_sats: u64,
    out_script: [*c]u8,
    out_script_len: *usize,
) c_int {
    const script = ordlock.lock(
        alloc,
        seller_pkh[0..20].*,
        pay_pkh[0..20].*,
        price_sats,
    ) catch return ERR_ALLOC;
    defer alloc.free(script);

    return copyToOut(script, out_script, out_script_len);
}
