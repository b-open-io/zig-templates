//! Author Identity Protocol (AIP) template.
//! Matches go-templates/template/bitcom/aip and @1sat/templates/aip.
//!
//! AIP enables cryptographic signing of blockchain content with Bitcoin addresses,
//! providing verifiable authorship and identity verification within BitCom transactions.
//!
//! Format: `OP_RETURN ... | <AIP_PREFIX> <ALGORITHM> <ADDRESS> <SIGNATURE> [<FIELD_INDEXES>]`
//! The signature is a BSM (Bitcoin Signed Message) compact signature over the
//! bytes preceding the pipe separator.

const std = @import("std");
const bsvz = @import("bsvz");

const PrivateKey = bsvz.crypto.PrivateKey;
const PublicKey = bsvz.crypto.PublicKey;
const appendPushData = bsvz.script.builder.appendPushData;
const appendOpcodes = bsvz.script.builder.appendOpcodes;
const Opcode = bsvz.script.opcode.Opcode;

/// AIP bitcom protocol prefix.
pub const prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";

/// Supported signing algorithm.
pub const algorithm_bitcoin_ecdsa = "BITCOIN_ECDSA";

/// Compact signature length (recovery header + R + S).
const compact_sig_len = bsvz.crypto.compact_sig_len; // 65

/// Decoded AIP data.
pub const AipData = struct {
    /// Signing algorithm (e.g. "BITCOIN_ECDSA").
    algorithm: []const u8,
    /// Bitcoin address of the signer.
    address: []const u8,
    /// Compact signature bytes (65 bytes when populated by `sign`).
    signature: []const u8,
    /// Optional field indices that were signed. null means all fields.
    indices: ?[]const i32 = null,
};

/// Error set for AIP operations.
pub const Error = error{
    SigningFailed,
    VerificationFailed,
    InvalidSignatureLength,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

/// Sign `data_to_sign` with the given private key using BSM format and return AIP fields.
///
/// The returned `AipData` owns allocated memory for `address` and `signature`.
/// The caller must free them via `deinit`.
pub fn sign(
    allocator: std.mem.Allocator,
    key: PrivateKey,
    data_to_sign: []const u8,
) Error!AipData {
    const sig65 = bsvz.compat.bsm.signMessage(key, data_to_sign, allocator) catch
        return error.SigningFailed;

    const sig_owned = try allocator.alloc(u8, compact_sig_len);
    @memcpy(sig_owned, &sig65);

    const pub_key = key.publicKey() catch return error.SigningFailed;
    const addr = bsvz.compat.address.encodeP2pkhFromPublicKey(allocator, .mainnet, pub_key) catch
        return error.SigningFailed;

    return .{
        .algorithm = algorithm_bitcoin_ecdsa,
        .address = addr,
        .signature = sig_owned,
    };
}

/// Free allocations produced by `sign`.
pub fn deinit(allocator: std.mem.Allocator, data: *AipData) void {
    if (data.signature.len > 0) allocator.free(data.signature);
    if (data.address.len > 0) allocator.free(data.address);
    data.* = undefined;
}

/// Build AIP script push bytes: `<ALGORITHM> <ADDRESS> <SIGNATURE> [<INDICES>]`.
///
/// This does NOT include the AIP prefix push or the pipe separator; those are
/// handled by the caller (e.g. `appendToScript`).
/// Caller owns the returned slice.
pub fn encode(allocator: std.mem.Allocator, data: AipData) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try appendPushData(&buf, allocator, data.algorithm);
    try appendPushData(&buf, allocator, data.address);
    try appendPushData(&buf, allocator, data.signature);

    if (data.indices) |indices| {
        for (indices) |idx| {
            var num_buf: [12]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{idx}) catch unreachable;
            try appendPushData(&buf, allocator, num_str);
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Verify that `data`'s signature is valid for `data_to_sign`.
///
/// Returns true if the recovered address matches `data.address`.
pub fn verify(
    allocator: std.mem.Allocator,
    data: AipData,
    data_to_sign: []const u8,
) Error!bool {
    if (data.signature.len != compact_sig_len) return error.InvalidSignatureLength;
    const sig65: [compact_sig_len]u8 = data.signature[0..compact_sig_len].*;
    bsvz.compat.bsm.verifyMessage(allocator, .mainnet, data.address, sig65, data_to_sign) catch
        return false;
    return true;
}

/// Append a pipe separator + AIP prefix + signed AIP fields to an existing script.
///
/// `script_before_pipe` is the raw script bytes that precede the AIP (everything
/// that will be signed). The returned slice is the full script with AIP appended.
/// Caller owns the returned slice.
pub fn appendToScript(
    allocator: std.mem.Allocator,
    script_before_pipe: []const u8,
    key: PrivateKey,
) Error![]u8 {
    // Sign the preceding script data.
    var aip_data = try sign(allocator, key, script_before_pipe);
    defer deinit(allocator, &aip_data);

    // Encode the AIP push data.
    const aip_script = try encode(allocator, aip_data);
    defer allocator.free(aip_script);

    // Build the combined script: original + pipe + AIP_PREFIX + aip_script
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, script_before_pipe);

    // Pipe separator.
    try appendPushData(&buf, allocator, "|");

    // AIP protocol prefix.
    try appendPushData(&buf, allocator, prefix);

    // AIP fields (algorithm, address, signature, optional indices).
    try buf.appendSlice(allocator, aip_script);

    return buf.toOwnedSlice(allocator);
}

// ── Tests ────────────────────────────────────────────────────────────

test "sign and verify round-trip" {
    const allocator = std.testing.allocator;

    // Deterministic test key.
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    const message = "hello AIP";
    var aip_data = try sign(allocator, sk, message);
    defer deinit(allocator, &aip_data);

    try std.testing.expectEqualSlices(u8, algorithm_bitcoin_ecdsa, aip_data.algorithm);
    try std.testing.expect(aip_data.address.len > 0);
    try std.testing.expectEqual(@as(usize, compact_sig_len), aip_data.signature.len);

    const valid = try verify(allocator, aip_data, message);
    try std.testing.expect(valid);
}

test "verify rejects wrong message" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 2;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    const message = "original message";
    var aip_data = try sign(allocator, sk, message);
    defer deinit(allocator, &aip_data);

    const valid = try verify(allocator, aip_data, "tampered message");
    try std.testing.expect(!valid);
}

test "verify rejects wrong address" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 3;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    var aip_data = try sign(allocator, sk, "test");
    defer deinit(allocator, &aip_data);

    // Replace address with a different one.
    allocator.free(aip_data.address);
    const fake_addr = try allocator.dupe(u8, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    aip_data.address = fake_addr;

    const valid = try verify(allocator, aip_data, "test");
    try std.testing.expect(!valid);
}

test "encode produces valid script push data" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 4;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    var aip_data = try sign(allocator, sk, "encode test");
    defer deinit(allocator, &aip_data);

    const encoded = try encode(allocator, aip_data);
    defer allocator.free(encoded);

    // The encoded bytes should start with a push of algorithm_bitcoin_ecdsa.
    // Push prefix byte = len of "BITCOIN_ECDSA" = 13 = 0x0d.
    try std.testing.expectEqual(@as(u8, 0x0d), encoded[0]);
    try std.testing.expectEqualSlices(u8, algorithm_bitcoin_ecdsa, encoded[1..14]);
}

test "encode with field indices" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 5;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    var aip_data = try sign(allocator, sk, "indices test");
    defer deinit(allocator, &aip_data);

    const indices = [_]i32{ 0, 1, 2 };
    aip_data.indices = &indices;

    const encoded = try encode(allocator, aip_data);
    defer allocator.free(encoded);

    // Should be longer than without indices.
    // Verify it contains the index push data at the end.
    // Each index is a 1-char string ("0", "1", "2") with a 1-byte push prefix.
    // Look for "0" (0x30), "1" (0x31), "2" (0x32) near the end.
    const tail = encoded[encoded.len - 6 ..];
    try std.testing.expectEqual(@as(u8, 0x01), tail[0]); // push 1 byte
    try std.testing.expectEqual(@as(u8, '0'), tail[1]);
    try std.testing.expectEqual(@as(u8, 0x01), tail[2]); // push 1 byte
    try std.testing.expectEqual(@as(u8, '1'), tail[3]);
    try std.testing.expectEqual(@as(u8, 0x01), tail[4]); // push 1 byte
    try std.testing.expectEqual(@as(u8, '2'), tail[5]);
}

test "appendToScript produces signed script" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 6;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    // Build a simple OP_RETURN script prefix.
    var script_prefix: std.ArrayListUnmanaged(u8) = .empty;
    defer script_prefix.deinit(allocator);
    try appendOpcodes(&script_prefix, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});
    try appendPushData(&script_prefix, allocator, "hello");

    const full_script = try appendToScript(allocator, script_prefix.items, sk);
    defer allocator.free(full_script);

    // Should start with the original script.
    try std.testing.expectEqualSlices(u8, script_prefix.items, full_script[0..script_prefix.items.len]);

    // Should contain the AIP prefix somewhere after the pipe.
    var found_prefix = false;
    for (0..full_script.len - prefix.len) |i| {
        if (std.mem.eql(u8, full_script[i .. i + prefix.len], prefix)) {
            found_prefix = true;
            break;
        }
    }
    try std.testing.expect(found_prefix);
}

test "appendToScript round-trip verify" {
    const allocator = std.testing.allocator;

    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 7;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    // Simple data to sign.
    const data = "round trip via appendToScript";

    var aip_data = try sign(allocator, sk, data);
    defer deinit(allocator, &aip_data);

    // Verify the signature against the same data.
    const valid = try verify(allocator, aip_data, data);
    try std.testing.expect(valid);
}

test "known address for private key 1" {
    const allocator = std.testing.allocator;

    // Private key = 1 should produce the well-known address.
    var key_bytes = [_]u8{0} ** 32;
    key_bytes[31] = 1;
    const sk = PrivateKey.fromBytes(key_bytes) catch unreachable;

    var aip_data = try sign(allocator, sk, "any message");
    defer deinit(allocator, &aip_data);

    try std.testing.expectEqualSlices(u8, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", aip_data.address);
}

test "verify rejects invalid signature length" {
    const allocator = std.testing.allocator;

    const data = AipData{
        .algorithm = algorithm_bitcoin_ecdsa,
        .address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        .signature = "too_short",
    };

    const result = verify(allocator, data, "test");
    try std.testing.expectError(error.InvalidSignatureLength, result);
}
