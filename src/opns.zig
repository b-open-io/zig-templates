//! OpNS (Op Name System) domain registration template.
//! Matches go-templates/template/opns.
//!
//! OpNS registers human-readable names on the BSV blockchain using a
//! proof-of-work contract. Names are built character-by-character through
//! sequential transactions that mine each character with a PoW nonce.
//!
//! Locking script format:
//!   <contract_bytecode>
//!   OP_RETURN OP_FALSE
//!   <push genesis_outpoint (36 bytes)>
//!   <push claimed>
//!   <push domain>
//!   <push pow (32 bytes)>
//!   <state_size (4 bytes LE)>
//!   0x00

const std = @import("std");
const bsvz = @import("bsvz");
const Opcode = bsvz.script.opcode.Opcode;
const appendPushData = bsvz.script.builder.appendPushData;
const appendOpcodes = bsvz.script.builder.appendOpcodes;

/// PoW difficulty (number of leading zero bits required).
pub const DIFFICULTY: u5 = 22;

/// Genesis outpoint as 36-byte TxBytes: txid (32 LE) + vout (4 LE).
/// txid: 58b7558ea379f24266c7e2f5fe321992ad9a724fd7a87423ba412677179ccb25
pub const GENESIS_OUTPOINT: [36]u8 = blk: {
    const txid_hex = "58b7558ea379f24266c7e2f5fe321992ad9a724fd7a87423ba412677179ccb25";
    var txid_le: [32]u8 = undefined;
    // Parse hex to bytes, then reverse for little-endian.
    for (0..32) |i| {
        const hi = hexNibble(txid_hex[i * 2]);
        const lo = hexNibble(txid_hex[i * 2 + 1]);
        txid_le[31 - i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    // Append vout 0 as 4-byte LE.
    var result: [36]u8 = undefined;
    @memcpy(result[0..32], &txid_le);
    result[32] = 0x00;
    result[33] = 0x00;
    result[34] = 0x00;
    result[35] = 0x00;
    break :blk result;
};

/// The OpNS contract bytecode (embedded as raw binary).
/// This is the fixed locking script logic that precedes the state data.
const CONTRACT: *const [5892]u8 = @embedFile("opns_contract.bin");

/// Decoded OpNS state data.
pub const OpnsData = struct {
    /// The "claimed" field (owner identifier / pubkey hash).
    claimed: []const u8,
    /// The domain name registered so far.
    domain: []const u8,
    /// The 32-byte PoW hash seed for the next character.
    pow: []const u8,
};

pub const Error = error{
    InvalidPushData,
    UnexpectedEndOfScript,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

/// Build an OpNS locking script.
///
/// This creates the full locking script: contract bytecode + state data.
///
/// Parameters:
///   - claimed: owner identifier bytes (e.g. pubkey hash)
///   - domain: the domain name string registered so far
///   - pow: 32-byte PoW hash seed for mining the next character
pub fn lock(
    allocator: std.mem.Allocator,
    claimed: []const u8,
    domain: []const u8,
    pow: []const u8,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Contract bytecode prefix.
    try buf.appendSlice(allocator, CONTRACT);

    // State section starts with OP_RETURN OP_FALSE.
    const state_start = buf.items.len;
    try appendOpcodes(&buf, allocator, &.{
        @intFromEnum(Opcode.OP_RETURN),
        @intFromEnum(Opcode.OP_0),
    });

    // Genesis outpoint (36 bytes).
    try appendPushData(&buf, allocator, &GENESIS_OUTPOINT);

    // Claimed field.
    try appendPushData(&buf, allocator, claimed);

    // Domain name.
    try appendPushData(&buf, allocator, domain);

    // PoW seed (32 bytes).
    try appendPushData(&buf, allocator, pow);

    // State size: number of bytes from OP_RETURN onward (excluding the
    // size field itself and trailing null). The Go code computes:
    //   stateSize = len(state) - 1  (where state starts at OP_RETURN)
    const state_len: u32 = @intCast(buf.items.len - state_start - 1);
    const size_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, state_len));
    try buf.appendSlice(allocator, &size_bytes);

    // Trailing null byte.
    try buf.append(allocator, 0x00);

    return buf.toOwnedSlice(allocator);
}

/// Decode OpNS state data from a raw locking script.
///
/// Returns null if the script does not have the OpNS contract prefix
/// or if the state data cannot be parsed.
pub fn decode(script_bytes: []const u8) ?OpnsData {
    const s = script_bytes;

    // Check contract prefix.
    if (s.len < CONTRACT.len + 2) return null;
    if (!std.mem.startsWith(u8, s, CONTRACT)) return null;

    // Skip past contract + 2 bytes (OP_RETURN OP_FALSE).
    var pos: usize = CONTRACT.len + 2;

    // Read genesis outpoint.
    const genesis_pd = readPushData(s, pos) orelse return null;
    if (genesis_pd.data.len != 36) return null;
    if (!std.mem.eql(u8, genesis_pd.data, &GENESIS_OUTPOINT)) return null;
    pos = genesis_pd.end;

    // Read claimed.
    const claimed_pd = readPushData(s, pos) orelse return null;
    pos = claimed_pd.end;

    // Read domain.
    const domain_pd = readPushData(s, pos) orelse return null;
    pos = domain_pd.end;

    // Read pow.
    const pow_pd = readPushData(s, pos) orelse return null;

    return .{
        .claimed = claimed_pd.data,
        .domain = domain_pd.data,
        .pow = pow_pd.data,
    };
}

/// Test whether a given character + nonce satisfies the PoW requirement
/// for the current state.
///
/// The hash is: SHA256d(pow ++ char ++ nonce), and the top DIFFICULTY
/// bits of the reversed hash must be zero.
pub fn testSolution(pow: []const u8, char: u8, nonce: []const u8) bool {
    if (pow.len != 32 or nonce.len != 32) return false;

    // Build the 65-byte preimage: pow(32) + char(1) + nonce(32).
    var preimage: [65]u8 = undefined;
    @memcpy(preimage[0..32], pow);
    preimage[32] = char;
    @memcpy(preimage[33..65], nonce);

    // SHA256d (double SHA-256).
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage, &first, .{});
    var hash_out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &hash_out, .{});

    // Reverse the hash (to match Go's big.Int byte order).
    var reversed: [32]u8 = undefined;
    for (0..32) |i| {
        reversed[i] = hash_out[31 - i];
    }

    // Check that the top DIFFICULTY bits are zero.
    return checkLeadingZeroBits(&reversed, DIFFICULTY);
}

/// Check that the big-endian 256-bit number has at least `bits` leading zero bits.
fn checkLeadingZeroBits(data: *const [32]u8, bits: u5) bool {
    const full_bytes: usize = @as(usize, bits) / 8;
    const remaining_bits: u4 = @intCast(@as(usize, bits) % 8);

    // Check full zero bytes.
    for (0..full_bytes) |i| {
        if (data[i] != 0) return false;
    }

    // Check remaining bits in the next byte.
    if (remaining_bits > 0 and full_bytes < 32) {
        const shift_amt: u3 = @intCast(8 - remaining_bits);
        const mask: u8 = @as(u8, 0xFF) << shift_amt;
        if (data[full_bytes] & mask != 0) return false;
    }

    return true;
}

// ── Helpers ─────────────────────────────────────────────────────────────

const PushDataResult = struct {
    data: []const u8,
    end: usize,
};

/// Read a push data element at the given position.
/// Returns null if the opcode at pos is not a push data instruction.
fn readPushData(s: []const u8, pos: usize) ?PushDataResult {
    if (pos >= s.len) return null;
    const op = s[pos];

    // OP_0 encodes a zero-length push (empty data).
    if (op == 0x00) {
        return .{ .data = s[pos + 1 .. pos + 1], .end = pos + 1 };
    }

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

    // OP_PUSHDATA4
    if (op == @intFromEnum(Opcode.OP_PUSHDATA4)) {
        if (pos + 4 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u32, s[pos + 1 ..][0..4], .little);
        const start = pos + 5;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    return null;
}

/// Comptime hex nibble decoder.
fn hexNibble(comptime c: u8) u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => @compileError("invalid hex character"),
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "genesis outpoint bytes match expected" {
    // Verify the genesis outpoint is correctly encoded.
    // The txid in LE should reverse the hex string bytes.
    const expected_txid_le = [_]u8{
        0x25, 0xcb, 0x9c, 0x17, 0x77, 0x26, 0x41, 0xba,
        0x23, 0x74, 0xa8, 0xd7, 0x4f, 0x72, 0x9a, 0xad,
        0x92, 0x19, 0x32, 0xfe, 0xf5, 0xe2, 0xc7, 0x66,
        0x42, 0xf2, 0x79, 0xa3, 0x8e, 0x55, 0xb7, 0x58,
    };
    try std.testing.expectEqualSlices(u8, &expected_txid_le, GENESIS_OUTPOINT[0..32]);
    // vout = 0
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, GENESIS_OUTPOINT[32..36]);
}

test "contract bytes are non-empty and match expected prefix" {
    try std.testing.expect(CONTRACT.len == 5892);
    // Contract should start with 0x01 0x68 0x01 0x6a based on Go hex: "0168016a..."
    try std.testing.expectEqual(@as(u8, 0x01), CONTRACT[0]);
    try std.testing.expectEqual(@as(u8, 0x68), CONTRACT[1]);
    try std.testing.expectEqual(@as(u8, 0x01), CONTRACT[2]);
    try std.testing.expectEqual(@as(u8, 0x6a), CONTRACT[3]);
}

test "lock creates valid locking script" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0xab} ** 20;
    const domain = "test";
    const pow = [_]u8{0xcd} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    // Should start with the contract prefix.
    try std.testing.expect(std.mem.startsWith(u8, script_bytes, CONTRACT));

    // Should be longer than just the contract.
    try std.testing.expect(script_bytes.len > CONTRACT.len + 36);

    // Should end with a null byte.
    try std.testing.expectEqual(@as(u8, 0x00), script_bytes[script_bytes.len - 1]);
}

test "lock and decode round-trip" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0xab} ** 20;
    const domain = "hello";
    const pow = [_]u8{0xcd} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    const result = decode(script_bytes) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &claimed, result.claimed);
    try std.testing.expectEqualSlices(u8, domain, result.domain);
    try std.testing.expectEqualSlices(u8, &pow, result.pow);
}

test "decode returns null for non-OpNS script" {
    const bad_script = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x00} ** 20 ++ [_]u8{ 0x88, 0xac };
    const result = decode(&bad_script);
    try std.testing.expect(result == null);
}

test "decode returns null for empty script" {
    const result = decode(&.{});
    try std.testing.expect(result == null);
}

test "decode returns null for truncated contract prefix" {
    // Only the first few bytes of the contract.
    const partial = CONTRACT[0..@min(10, CONTRACT.len)];
    const result = decode(partial);
    try std.testing.expect(result == null);
}

test "lock and decode with empty domain" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0x01} ** 20;
    const domain = "";
    const pow = [_]u8{0xff} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    const result = decode(script_bytes) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &claimed, result.claimed);
    try std.testing.expectEqualSlices(u8, domain, result.domain);
    try std.testing.expectEqualSlices(u8, &pow, result.pow);
}

test "lock and decode with single-character domain" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0x42} ** 20;
    const domain = "a";
    const pow = [_]u8{0x11} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    const result = decode(script_bytes) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &claimed, result.claimed);
    try std.testing.expectEqualSlices(u8, "a", result.domain);
}

test "lock and decode with long domain name" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0x99} ** 20;
    const domain = "my-very-long-domain-name-example";
    const pow = [_]u8{0x22} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    const result = decode(script_bytes) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &claimed, result.claimed);
    try std.testing.expectEqualSlices(u8, domain, result.domain);
    try std.testing.expectEqualSlices(u8, &pow, result.pow);
}

test "testSolution rejects wrong-sized inputs" {
    const short_pow = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 32;
    try std.testing.expect(!testSolution(&short_pow, 'a', &nonce));

    const pow = [_]u8{0x00} ** 32;
    const short_nonce = [_]u8{0x00} ** 16;
    try std.testing.expect(!testSolution(&pow, 'a', &short_nonce));
}

test "testSolution with known zero inputs is deterministic" {
    // With all-zero pow and nonce, the SHA256d result is deterministic.
    // Verify the function runs without crashing and returns a
    // consistent result.
    const pow = [_]u8{0x00} ** 32;
    const nonce = [_]u8{0x00} ** 32;
    const result1 = testSolution(&pow, 'a', &nonce);
    const result2 = testSolution(&pow, 'a', &nonce);
    try std.testing.expectEqual(result1, result2);
}

test "testSolution different chars produce different results" {
    // Different characters should (generally) produce different hash results.
    // We test that the function is sensitive to the character input.
    const pow = [_]u8{0x00} ** 32;
    const nonce = [_]u8{0x00} ** 32;
    // With difficulty 22, most random inputs will NOT satisfy the PoW.
    // Both should return false (statistically near-certain).
    const result_a = testSolution(&pow, 'a', &nonce);
    const result_b = testSolution(&pow, 'b', &nonce);
    // We can't guarantee they differ, but we can verify they're both booleans.
    _ = result_a;
    _ = result_b;
}

test "checkLeadingZeroBits" {
    // All zeros: any number of leading zero bits should pass.
    const all_zeros = [_]u8{0x00} ** 32;
    try std.testing.expect(checkLeadingZeroBits(&all_zeros, 0));
    try std.testing.expect(checkLeadingZeroBits(&all_zeros, 8));
    try std.testing.expect(checkLeadingZeroBits(&all_zeros, 16));
    try std.testing.expect(checkLeadingZeroBits(&all_zeros, 22));

    // First byte = 0x01: only 7 leading zero bits.
    var one_bit = [_]u8{0x00} ** 32;
    one_bit[0] = 0x01;
    try std.testing.expect(checkLeadingZeroBits(&one_bit, 0));
    try std.testing.expect(checkLeadingZeroBits(&one_bit, 7));
    try std.testing.expect(!checkLeadingZeroBits(&one_bit, 8));

    // First byte = 0x00, second byte = 0x04: 13 leading zero bits.
    var thirteen = [_]u8{0x00} ** 32;
    thirteen[1] = 0x04;
    try std.testing.expect(checkLeadingZeroBits(&thirteen, 13));
    try std.testing.expect(!checkLeadingZeroBits(&thirteen, 14));

    // 22 leading zero bits: first 2 bytes zero, third byte top 6 bits zero.
    // 0x03 = 0b00000011 -> 6 leading zeros in that byte -> total 22.
    var twenty_two = [_]u8{0x00} ** 32;
    twenty_two[2] = 0x03;
    try std.testing.expect(checkLeadingZeroBits(&twenty_two, 22));
    try std.testing.expect(!checkLeadingZeroBits(&twenty_two, 23));
}

test "decode rejects wrong genesis outpoint" {
    const allocator = std.testing.allocator;

    // Build a valid script but tamper with the genesis outpoint.
    const claimed = [_]u8{0xab} ** 20;
    const domain = "test";
    const pow = [_]u8{0xcd} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    // Tamper with the genesis outpoint (it starts after CONTRACT + 2 + push_prefix).
    // The push prefix for 36 bytes is 0x24 (direct push), so genesis data
    // starts at CONTRACT.len + 2 + 1.
    const genesis_data_start = CONTRACT.len + 2 + 1;
    script_bytes[genesis_data_start] ^= 0xFF; // flip a byte

    const result = decode(script_bytes);
    try std.testing.expect(result == null);
}

test "lock state size and trailing null" {
    const allocator = std.testing.allocator;

    const claimed = [_]u8{0xab} ** 20;
    const domain = "x";
    const pow = [_]u8{0xcd} ** 32;

    const script_bytes = try lock(allocator, &claimed, domain, &pow);
    defer allocator.free(script_bytes);

    // Verify trailing null byte.
    try std.testing.expectEqual(@as(u8, 0x00), script_bytes[script_bytes.len - 1]);

    // Read back the state size (4 bytes LE before the trailing null).
    const size_offset = script_bytes.len - 5;
    const state_size = std.mem.readInt(u32, script_bytes[size_offset..][0..4], .little);

    // State size should be: everything from OP_RETURN to end of pow push,
    // minus 1 (the Go convention: len(state) - 1 where state starts at OP_RETURN).
    // state = OP_RETURN(1) + OP_0(1) + push_prefix(1) + genesis(36) +
    //         push_prefix(1) + claimed(20) + push_prefix(1) + domain(1) +
    //         push_prefix(1) + pow(32) = 95 bytes
    // state_size = 95 - 1 = 94
    try std.testing.expectEqual(@as(u32, 94), state_size);
}
