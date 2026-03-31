//! Lock (CLTV timelock) template.
//! Matches go-templates/template/lockup and @1sat/templates/lock.
//!
//! Locking script format:
//!   <block_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!   OP_DUP OP_HASH160 <20-byte pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
//!
//! The output can only be spent after the specified block height.

const std = @import("std");
const bsvz = @import("bsvz");
const Opcode = bsvz.script.opcode.Opcode;
const appendPushData = bsvz.script.builder.appendPushData;
const appendOpcodes = bsvz.script.builder.appendOpcodes;

/// Decoded lock data.
pub const LockData = struct {
    /// Block height at which the output becomes spendable.
    block_height: u32,
    /// 20-byte HASH160 of the public key that can spend after unlock.
    pubkey_hash: [20]u8,
};

pub const Error = error{
    InvalidScript,
    UnexpectedEndOfScript,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

/// Encode a block height as a Bitcoin script number (minimal encoding, little-endian).
/// Returns the number of bytes written into `buf`.
fn encodeScriptNumber(value: u32, buf: *[5]u8) u8 {
    if (value == 0) {
        // OP_0 is handled separately; for push data, zero is empty bytes.
        // But block_height=0 is nonsensical; we still encode it correctly.
        return 0;
    }

    var v = value;
    var len: u8 = 0;
    while (v > 0) {
        buf[len] = @truncate(v & 0xff);
        len += 1;
        v >>= 8;
    }

    // If the high bit of the last byte is set, append a 0x00 byte
    // to indicate positive sign (Bitcoin script number encoding).
    if (buf[len - 1] & 0x80 != 0) {
        buf[len] = 0x00;
        len += 1;
    }

    return len;
}

/// Decode a Bitcoin script number from minimally-encoded little-endian bytes.
/// Returns null if the data is empty or longer than 5 bytes.
fn decodeScriptNumber(data: []const u8) ?u32 {
    if (data.len == 0) return 0;
    if (data.len > 5) return null;

    // Negative script numbers are not valid block heights.
    if (data[data.len - 1] & 0x80 != 0) return null;

    var result: u64 = 0;
    for (data, 0..) |byte, i| {
        result |= @as(u64, byte) << @intCast(i * 8);
    }

    if (result > std.math.maxInt(u32)) return null;
    return @intCast(result);
}

/// Build a CLTV locking script as raw script bytes.
///
/// Format:
///   <block_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
///   OP_DUP OP_HASH160 <push 20 bytes> <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn lock(
    allocator: std.mem.Allocator,
    pubkey_hash: *const [20]u8,
    block_height: u32,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Push block height as script number
    var num_buf: [5]u8 = undefined;
    const num_len = encodeScriptNumber(block_height, &num_buf);
    if (num_len == 0) {
        // block_height == 0: push OP_0
        try appendOpcodes(&buf, allocator, &.{@intFromEnum(Opcode.OP_0)});
    } else {
        try appendPushData(&buf, allocator, num_buf[0..num_len]);
    }

    // OP_CHECKLOCKTIMEVERIFY OP_DROP
    try appendOpcodes(&buf, allocator, &.{
        @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY),
        @intFromEnum(Opcode.OP_DROP),
    });

    // P2PKH: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    try appendOpcodes(&buf, allocator, &.{
        @intFromEnum(Opcode.OP_DUP),
        @intFromEnum(Opcode.OP_HASH160),
    });
    try appendPushData(&buf, allocator, pubkey_hash);
    try appendOpcodes(&buf, allocator, &.{
        @intFromEnum(Opcode.OP_EQUALVERIFY),
        @intFromEnum(Opcode.OP_CHECKSIG),
    });

    return buf.toOwnedSlice(allocator);
}

/// Read push data at the given position in the script. Returns the data slice
/// and the position after the push, or null if not a push opcode.
fn readPushData(s: []const u8, pos: usize) ?struct { data: []const u8, end: usize } {
    if (pos >= s.len) return null;
    const op = s[pos];

    // Direct push: 0x01..0x4b (1-75 bytes)
    if (op >= 0x01 and op <= 0x4b) {
        const data_len: usize = op;
        const start = pos + 1;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    // OP_PUSHDATA1
    if (op == @intFromEnum(Opcode.OP_PUSHDATA1)) {
        if (pos + 1 >= s.len) return null;
        const data_len: usize = s[pos + 1];
        const start = pos + 2;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    // OP_PUSHDATA2
    if (op == @intFromEnum(Opcode.OP_PUSHDATA2)) {
        if (pos + 2 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u16, s[pos + 1 ..][0..2], .little);
        const start = pos + 3;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    return null;
}

/// Decode a CLTV lock script into its components.
///
/// Expected format:
///   <push block_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
///   OP_DUP OP_HASH160 <push 20> <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
///
/// Returns null if the script does not match the expected pattern.
pub fn decode(script_bytes: []const u8) ?LockData {
    var pos: usize = 0;

    // Read block height push data (or OP_0 for height 0)
    var height_value: u32 = 0;
    if (pos < script_bytes.len and script_bytes[pos] == @intFromEnum(Opcode.OP_0)) {
        height_value = 0;
        pos += 1;
    } else if (readPushData(script_bytes, pos)) |pd| {
        height_value = decodeScriptNumber(pd.data) orelse return null;
        pos = pd.end;
    } else {
        return null;
    }

    // Expect OP_CHECKLOCKTIMEVERIFY OP_DROP
    if (pos + 2 > script_bytes.len) return null;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY)) return null;
    pos += 1;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_DROP)) return null;
    pos += 1;

    // Expect OP_DUP OP_HASH160
    if (pos + 2 > script_bytes.len) return null;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_DUP)) return null;
    pos += 1;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_HASH160)) return null;
    pos += 1;

    // Read 20-byte pubkey hash
    const pkh_pd = readPushData(script_bytes, pos) orelse return null;
    if (pkh_pd.data.len != 20) return null;
    pos = pkh_pd.end;

    // Expect OP_EQUALVERIFY OP_CHECKSIG
    if (pos + 2 > script_bytes.len) return null;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_EQUALVERIFY)) return null;
    pos += 1;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_CHECKSIG)) return null;
    pos += 1;

    // Ensure we consumed the entire script
    if (pos != script_bytes.len) return null;

    return LockData{
        .block_height = height_value,
        .pubkey_hash = pkh_pd.data[0..20].*,
    };
}

/// Extract just the block height from a CLTV lock script without full decoding.
/// Returns null if the script does not start with a valid height push followed
/// by OP_CHECKLOCKTIMEVERIFY.
pub fn unlock_height(script_bytes: []const u8) ?u32 {
    var pos: usize = 0;

    // Read block height
    var height_value: u32 = 0;
    if (pos < script_bytes.len and script_bytes[pos] == @intFromEnum(Opcode.OP_0)) {
        height_value = 0;
        pos += 1;
    } else if (readPushData(script_bytes, pos)) |pd| {
        height_value = decodeScriptNumber(pd.data) orelse return null;
        pos = pd.end;
    } else {
        return null;
    }

    // Verify OP_CHECKLOCKTIMEVERIFY follows
    if (pos >= script_bytes.len) return null;
    if (script_bytes[pos] != @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY)) return null;

    return height_value;
}

// ── Tests ────────────────────────────────────────────────────────────

test "lock creates valid CLTV script" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0xab} ** 20;
    const block_height: u32 = 800_000;

    const script = try lock(allocator, &pkh, block_height);
    defer allocator.free(script);

    // 800000 = 0x0C3500 -> little-endian: 00 35 0C
    // Script: <push 3> 00 35 0C  OP_CLTV OP_DROP  OP_DUP OP_HASH160 <push 20> <pkh*20> OP_EQUALVERIFY OP_CHECKSIG
    try std.testing.expect(script.len > 0);

    // Verify OP_CHECKLOCKTIMEVERIFY is present
    var found_cltv = false;
    for (script) |byte| {
        if (byte == @intFromEnum(Opcode.OP_CHECKLOCKTIMEVERIFY)) {
            found_cltv = true;
            break;
        }
    }
    try std.testing.expect(found_cltv);

    // Verify pubkey hash is embedded
    try std.testing.expect(std.mem.indexOf(u8, script, &pkh) != null);
}

test "decode round-trip" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0xde} ** 20;
    const block_height: u32 = 850_000;

    const script = try lock(allocator, &pkh, block_height);
    defer allocator.free(script);

    const data = decode(script) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(block_height, data.block_height);
    try std.testing.expectEqualSlices(u8, &pkh, &data.pubkey_hash);
}

test "decode round-trip various block heights" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0x42} ** 20;

    const heights = [_]u32{
        1, // minimal 1-byte
        127, // max 1-byte without sign bit
        128, // requires sign-extension byte
        255, // boundary
        256, // 2 bytes
        32767, // max 2-byte without sign bit
        32768, // requires sign-extension
        65535, // 2 bytes full
        800_000, // typical current height
        2_000_000, // future height
        0x7FFFFFFF, // max positive in 4 bytes
    };

    for (heights) |h| {
        const script = try lock(allocator, &pkh, h);
        defer allocator.free(script);

        const data = decode(script) orelse {
            std.debug.print("Failed to decode for height {}\n", .{h});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqual(h, data.block_height);
        try std.testing.expectEqualSlices(u8, &pkh, &data.pubkey_hash);
    }
}

test "unlock_height extracts block height" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0x01} ** 20;
    const block_height: u32 = 900_000;

    const script = try lock(allocator, &pkh, block_height);
    defer allocator.free(script);

    const h = unlock_height(script) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(block_height, h);
}

test "unlock_height returns null for non-CLTV script" {
    // P2PKH script (no CLTV)
    const p2pkh = [_]u8{
        0x76, 0xa9, 0x14,
    } ++ [_]u8{0xab} ** 20 ++ [_]u8{
        0x88, 0xac,
    };
    const result = unlock_height(&p2pkh);
    try std.testing.expect(result == null);
}

test "decode returns null for invalid scripts" {
    // Empty
    try std.testing.expect(decode(&.{}) == null);

    // Just OP_RETURN
    try std.testing.expect(decode(&.{0x6a}) == null);

    // Valid CLTV prefix but truncated (no P2PKH)
    try std.testing.expect(decode(&.{ 0x01, 0x01, 0xb1, 0x75 }) == null);

    // Valid structure but wrong PKH length (19 bytes)
    const bad_pkh = [_]u8{ 0x01, 0x01, 0xb1, 0x75, 0x76, 0xa9, 0x13 } ++ [_]u8{0xaa} ** 19 ++ [_]u8{ 0x88, 0xac };
    try std.testing.expect(decode(&bad_pkh) == null);
}

test "decode returns null for script with trailing bytes" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0xcc} ** 20;

    const script = try lock(allocator, &pkh, 500_000);
    defer allocator.free(script);

    // Append extra byte -- should fail strict decode
    var extended = try allocator.alloc(u8, script.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..script.len], script);
    extended[script.len] = 0xff;

    try std.testing.expect(decode(extended) == null);
}

test "block height 0 round-trip" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0x55} ** 20;

    const script = try lock(allocator, &pkh, 0);
    defer allocator.free(script);

    const data = decode(script) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0), data.block_height);
    try std.testing.expectEqualSlices(u8, &pkh, &data.pubkey_hash);
}

test "script byte layout for known height" {
    const allocator = std.testing.allocator;
    const pkh = [_]u8{0xaa} ** 20;
    // Height 500000 = 0x07A120 -> LE bytes: 20 A1 07
    const block_height: u32 = 500_000;

    const script = try lock(allocator, &pkh, block_height);
    defer allocator.free(script);

    // Expected layout:
    // [0]    = 0x03 (push 3 bytes)
    // [1..4] = 20 A1 07 (height LE)
    // [4]    = 0xB1 (OP_CHECKLOCKTIMEVERIFY)
    // [5]    = 0x75 (OP_DROP)
    // [6]    = 0x76 (OP_DUP)
    // [7]    = 0xA9 (OP_HASH160)
    // [8]    = 0x14 (push 20 bytes)
    // [9..29]= pubkey_hash
    // [29]   = 0x88 (OP_EQUALVERIFY)
    // [30]   = 0xAC (OP_CHECKSIG)
    try std.testing.expectEqual(@as(usize, 31), script.len);
    try std.testing.expectEqual(@as(u8, 0x03), script[0]); // push 3
    try std.testing.expectEqual(@as(u8, 0x20), script[1]); // LE byte 0
    try std.testing.expectEqual(@as(u8, 0xA1), script[2]); // LE byte 1
    try std.testing.expectEqual(@as(u8, 0x07), script[3]); // LE byte 2
    try std.testing.expectEqual(@as(u8, 0xB1), script[4]); // OP_CHECKLOCKTIMEVERIFY
    try std.testing.expectEqual(@as(u8, 0x75), script[5]); // OP_DROP
    try std.testing.expectEqual(@as(u8, 0x76), script[6]); // OP_DUP
    try std.testing.expectEqual(@as(u8, 0xA9), script[7]); // OP_HASH160
    try std.testing.expectEqual(@as(u8, 0x14), script[8]); // push 20
    try std.testing.expectEqualSlices(u8, &pkh, script[9..29]);
    try std.testing.expectEqual(@as(u8, 0x88), script[29]); // OP_EQUALVERIFY
    try std.testing.expectEqual(@as(u8, 0xAC), script[30]); // OP_CHECKSIG
}
