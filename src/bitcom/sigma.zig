//! SIGMA signature (Type-42) template.
//! Successor to AIP — uses Type-42 derived keys instead of root key.
//! Format: `| SIG <algorithm> <address> <signature> <vin> [<index_count> <indices...>]`
//! Matches go-templates/template/bitcom/sigma and @1sat/templates/sigma.

const std = @import("std");
const bsvz = @import("bsvz");

const ec = bsvz.primitives.ec;
const bsm = bsvz.compat.bsm;
const address_mod = bsvz.compat.address;
const crypto_hash = bsvz.crypto.hash;
const script_builder = bsvz.script.builder;
const Opcode = bsvz.script.opcode.Opcode;

/// SIGMA prefix bytes: "SIGMA"
pub const prefix = "SIGMA";

/// Supported signature algorithms.
pub const Algorithm = enum {
    BSM,

    pub fn toBytes(self: Algorithm) []const u8 {
        return switch (self) {
            .BSM => "BSM",
        };
    }

    pub fn fromBytes(bytes: []const u8) !Algorithm {
        if (std.mem.eql(u8, bytes, "BSM")) return .BSM;
        return error.UnsupportedAlgorithm;
    }
};

/// Decoded SIGMA signature data.
pub const SigmaData = struct {
    algorithm: Algorithm,
    /// P2PKH address string of the signing key (base58check).
    address: []const u8,
    /// 65-byte compact BSM signature.
    signature: [65]u8,
    /// Input index whose outpoint is hashed into the signed message.
    vin: u32,
    /// Optional field indices specifying which output fields are signed.
    indices: ?[]const u32 = null,
};

/// Signs `data_to_sign` with `privkey` using BSM and returns a `SigmaData`.
///
/// The caller owns the returned `address` slice and must free it with `allocator`.
pub fn sign(
    allocator: std.mem.Allocator,
    privkey: ec.PrivateKey,
    data_to_sign: []const u8,
    vin: u32,
) !SigmaData {
    // Sign using BSM (Bitcoin Signed Message) — produces 65-byte compact signature
    const sig65 = try bsm.signMessage(privkey.inner, data_to_sign, allocator);

    // Derive the P2PKH address from the public key
    const pub_key = try privkey.publicKey();
    const addr = try address_mod.encodeP2pkhFromPublicKey(allocator, .mainnet, pub_key.inner);

    return .{
        .algorithm = .BSM,
        .address = addr,
        .signature = sig65,
        .vin = vin,
    };
}

/// Encodes `SigmaData` into SIGMA script bytes:
/// `<push "SIGMA"> <push algorithm> <push address> <push signature> <push vin_str> [<push index_count> <push indices...>]`
///
/// Caller owns the returned slice and must free it with `allocator`.
pub fn encode(allocator: std.mem.Allocator, sigma: *const SigmaData) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    // Push SIGMA prefix
    try script_builder.appendPushData(&out, allocator, prefix);

    // Push algorithm
    try script_builder.appendPushData(&out, allocator, sigma.algorithm.toBytes());

    // Push address
    try script_builder.appendPushData(&out, allocator, sigma.address);

    // Push signature (65 bytes)
    try script_builder.appendPushData(&out, allocator, &sigma.signature);

    // Push vin as ASCII decimal string
    var vin_buf: [10]u8 = undefined;
    const vin_str = std.fmt.bufPrint(&vin_buf, "{d}", .{sigma.vin}) catch unreachable;
    try script_builder.appendPushData(&out, allocator, vin_str);

    // Push optional indices
    if (sigma.indices) |indices| {
        // Push index count
        var count_buf: [10]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{indices.len}) catch unreachable;
        try script_builder.appendPushData(&out, allocator, count_str);

        // Push each index
        for (indices) |idx| {
            var idx_buf: [10]u8 = undefined;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch unreachable;
            try script_builder.appendPushData(&out, allocator, idx_str);
        }
    }

    return out.toOwnedSlice(allocator);
}

/// Verifies a SIGMA signature against `data_to_sign`.
///
/// Returns `true` if the recovered public key's address matches `sigma.address`.
pub fn verify(
    allocator: std.mem.Allocator,
    sigma: *const SigmaData,
    data_to_sign: []const u8,
) !bool {
    return switch (sigma.algorithm) {
        .BSM => {
            bsm.verifyMessage(
                allocator,
                .mainnet,
                sigma.address,
                sigma.signature,
                data_to_sign,
            ) catch return false;
            return true;
        },
    };
}

/// Signs the existing `script_bytes` and appends the SIGMA envelope.
///
/// The signed message is the SHA256 of the input script bytes.
/// Returns the combined script (original + pipe separator + SIGMA data).
/// Caller owns the returned slice and must free it with `allocator`.
pub fn appendToScript(
    allocator: std.mem.Allocator,
    script_bytes: []const u8,
    privkey: ec.PrivateKey,
    vin: u32,
) ![]u8 {
    // Hash the script data to create the message to sign
    const data_hash = crypto_hash.sha256(script_bytes);

    // Sign the hash
    var sigma = try sign(allocator, privkey, &data_hash.bytes, vin);
    defer allocator.free(sigma.address);

    // Encode the SIGMA data
    const sigma_bytes = try encode(allocator, &sigma);
    defer allocator.free(sigma_bytes);

    // Build: original_script || OP_PIPE_SEPARATOR || sigma_bytes
    // The pipe separator is push data of "|"
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, script_bytes);

    // Pipe separator: push "|"
    try script_builder.appendPushData(&out, allocator, "|");

    try out.appendSlice(allocator, sigma_bytes);

    return out.toOwnedSlice(allocator);
}

// ── Tests ──────────────────────────────────────────────────────────────

test "sign and verify roundtrip" {
    const allocator = std.testing.allocator;

    // Create a deterministic private key
    var key_bytes: [32]u8 = [_]u8{0} ** 32;
    key_bytes[31] = 42;
    const privkey = try ec.PrivateKey.fromBytes(key_bytes);

    const message = "hello sigma";

    // Sign
    var sigma = try sign(allocator, privkey, message, 0);
    defer allocator.free(sigma.address);

    // Verify algorithm
    try std.testing.expectEqual(Algorithm.BSM, sigma.algorithm);
    try std.testing.expectEqual(@as(u32, 0), sigma.vin);

    // Address should be a valid base58 string starting with '1'
    try std.testing.expect(sigma.address.len > 0);
    try std.testing.expect(sigma.address[0] == '1');

    // Verify the signature
    const valid = try verify(allocator, &sigma, message);
    try std.testing.expect(valid);

    // Verify with wrong message fails
    const invalid = try verify(allocator, &sigma, "wrong message");
    try std.testing.expect(!invalid);
}

test "sign and verify with Type-42 derived key" {
    const allocator = std.testing.allocator;

    const key_deriver = bsvz.primitives.key_deriver;

    // Create root key
    var root_bytes: [32]u8 = [_]u8{0} ** 32;
    root_bytes[31] = 42;
    const root_key = try ec.PrivateKey.fromBytes(root_bytes);
    const kd = key_deriver.KeyDeriver.init(root_key);

    // Create a counterparty
    var cp_bytes: [32]u8 = [_]u8{0} ** 32;
    cp_bytes[31] = 69;
    const cp_key = try ec.PrivateKey.fromBytes(cp_bytes);
    const cp_pub = try cp_key.publicKey();

    // Derive a Type-42 child key via BRC-43
    const protocol = key_deriver.Protocol{ .security_level = 2, .name = "sigma signing" };
    const derived_priv = try kd.derivePrivateKey(allocator, protocol, "msg-001", .{
        .type_ = .other,
        .public_key = cp_pub,
    });
    const message = "signed with derived key";

    // Sign with derived key
    var sigma = try sign(allocator, derived_priv, message, 0);
    defer allocator.free(sigma.address);

    // The address should differ from root key's address
    const root_pub = try root_key.publicKey();
    const root_addr = try address_mod.encodeP2pkhFromPublicKey(allocator, .mainnet, root_pub.inner);
    defer allocator.free(root_addr);
    try std.testing.expect(!std.mem.eql(u8, sigma.address, root_addr));

    // Verify succeeds
    const valid = try verify(allocator, &sigma, message);
    try std.testing.expect(valid);
}

test "encode produces valid script bytes" {
    const allocator = std.testing.allocator;

    var key_bytes: [32]u8 = [_]u8{0} ** 32;
    key_bytes[31] = 42;
    const privkey = try ec.PrivateKey.fromBytes(key_bytes);

    var sigma = try sign(allocator, privkey, "test", 3);
    defer allocator.free(sigma.address);

    const encoded = try encode(allocator, &sigma);
    defer allocator.free(encoded);

    // Should start with a push of "SIGMA" (5 bytes -> 0x05 length prefix + "SIGMA")
    try std.testing.expect(encoded.len > 5);
    try std.testing.expectEqual(@as(u8, 5), encoded[0]); // length prefix for 5-byte push
    try std.testing.expectEqualStrings(prefix, encoded[1..6]);
}

test "appendToScript signs and appends" {
    const allocator = std.testing.allocator;

    var key_bytes: [32]u8 = [_]u8{0} ** 32;
    key_bytes[31] = 42;
    const privkey = try ec.PrivateKey.fromBytes(key_bytes);

    // Some example script bytes (OP_RETURN + push data "hello")
    const original_script = &[_]u8{ 0x6a, 0x05 } ++ "hello";

    const result = try appendToScript(allocator, original_script, privkey, 0);
    defer allocator.free(result);

    // Result should start with the original script
    try std.testing.expectEqualSlices(u8, original_script, result[0..original_script.len]);

    // Should be longer than original (pipe separator + sigma envelope)
    try std.testing.expect(result.len > original_script.len + 10);
}

test "encode with indices" {
    const allocator = std.testing.allocator;

    const indices = [_]u32{ 0, 1, 5 };

    const sigma = SigmaData{
        .algorithm = .BSM,
        .address = "1TestAddress",
        .signature = [_]u8{0xAB} ** 65,
        .vin = 0,
        .indices = &indices,
    };

    const encoded = try encode(allocator, &sigma);
    defer allocator.free(encoded);

    // Verify prefix is present
    try std.testing.expectEqual(@as(u8, 5), encoded[0]);
    try std.testing.expectEqualStrings(prefix, encoded[1..6]);

    // The encoded result should contain the index count and indices
    // Just verify it's longer than a basic encode would be
    const sigma_no_indices = SigmaData{
        .algorithm = .BSM,
        .address = "1TestAddress",
        .signature = [_]u8{0xAB} ** 65,
        .vin = 0,
        .indices = null,
    };
    const encoded_no_indices = try encode(allocator, &sigma_no_indices);
    defer allocator.free(encoded_no_indices);

    try std.testing.expect(encoded.len > encoded_no_indices.len);
}

test "Algorithm fromBytes and toBytes roundtrip" {
    const algo = try Algorithm.fromBytes("BSM");
    try std.testing.expectEqual(Algorithm.BSM, algo);
    try std.testing.expectEqualStrings("BSM", algo.toBytes());
}

test "Algorithm fromBytes rejects unknown" {
    try std.testing.expectError(error.UnsupportedAlgorithm, Algorithm.fromBytes("UNKNOWN"));
}

test "verify rejects wrong address" {
    const allocator = std.testing.allocator;

    var key_bytes: [32]u8 = [_]u8{0} ** 32;
    key_bytes[31] = 42;
    const privkey = try ec.PrivateKey.fromBytes(key_bytes);

    const message = "hello sigma";

    const sigma = try sign(allocator, privkey, message, 0);
    defer allocator.free(sigma.address);

    // Tamper with address — use a different key's address
    var other_bytes: [32]u8 = [_]u8{0} ** 32;
    other_bytes[31] = 99;
    const other_key = try ec.PrivateKey.fromBytes(other_bytes);
    const other_pub = try other_key.publicKey();
    const wrong_addr = try address_mod.encodeP2pkhFromPublicKey(allocator, .mainnet, other_pub.inner);
    defer allocator.free(wrong_addr);

    // Create a sigma with wrong address but correct signature
    const tampered = SigmaData{
        .algorithm = sigma.algorithm,
        .address = wrong_addr,
        .signature = sigma.signature,
        .vin = sigma.vin,
    };

    const valid = try verify(allocator, &tampered, message);
    try std.testing.expect(!valid);
}
