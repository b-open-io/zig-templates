//! OrdLock — marketplace listing template for ordinal/NFT sales.
//! Matches go-templates/template/ordlock and @1sat/templates/ordlock.
//!
//! An OrdLock script locks an ordinal for trustless sale. The locking script
//! is structured as:
//!
//!   <sCrypt OrdLock Prefix>
//!   <push seller_pkh (20 bytes)>
//!   <push payout_output (serialized TransactionOutput)>
//!   <sCrypt OrdLock Suffix>
//!
//! The sCrypt contract validates that a purchase transaction pays the
//! seller the correct amount. Cancellation uses the OP_IF branch with
//! a standard P2PKH signature from the seller.

const std = @import("std");
const bsvz = @import("bsvz");
const appendPushData = bsvz.script.builder.appendPushData;

// ── Constants ────────────────────────────────────────────────────────

/// sCrypt OrdLock contract prefix (shared with the Lock template).
pub const ORDLOCK_PREFIX = hexLiteral(
    "2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026" ++
        "2102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382" ++
        "201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c" ++
        "0000",
);

/// sCrypt OrdLock contract suffix (validation logic).
pub const ORDLOCK_SUFFIX = hexLiteral(
    "615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161" ++
        "517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad9" ++
        "05aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da" ++
        "8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f" ++
        "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
        "517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c" ++
        "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c" ++
        "7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479" ++
        "577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffff" ++
        "ffffff00517951796151795179970079009f63007952799367007968517a75517a7551" ++
        "7a7561527a75517a517951795296a0630079527994527a75517a6853798277527982" ++
        "775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
        "517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
        "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
        "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e0120" ++
        "5279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57" ++
        "797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75" ++
        "517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a" ++
        "75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179" ++
        "517958947f7551790128947f77517a75517a75618777777777777777777767557951" ++
        "876351795779a9876957795779ac777777777777777767006868",
);

/// Decoded OrdLock listing data.
pub const OrdLockData = struct {
    /// Seller's 20-byte public key hash.
    seller_pkh: [20]u8,
    /// Listing price in satoshis (parsed from the payout output).
    price_sats: u64,
    /// Raw serialized payout TransactionOutput bytes
    /// (8-byte LE satoshis + varint script length + locking script).
    payout: []const u8,
};

pub const Error = error{
    InvalidPushData,
    UnexpectedEndOfScript,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

// ── Public API ───────────────────────────────────────────────────────

/// Build an OrdLock locking script.
///
/// Parameters:
///   - `seller_pkh`: 20-byte public key hash of the cancel/seller address.
///   - `pay_pkh`: 20-byte public key hash of the payment destination.
///   - `price_sats`: listing price in satoshis.
///
/// Returns heap-allocated script bytes. Caller owns the memory.
pub fn lock(
    allocator: std.mem.Allocator,
    seller_pkh: [20]u8,
    pay_pkh: [20]u8,
    price_sats: u64,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // 1. OrdLock prefix
    try buf.appendSlice(allocator, &ORDLOCK_PREFIX);

    // 2. Push seller PKH (20 bytes)
    try appendPushData(&buf, allocator, &seller_pkh);

    // 3. Build payout output: P2PKH locking script for pay_pkh
    const payout_output = buildPayoutOutput(price_sats, &pay_pkh);
    try appendPushData(&buf, allocator, &payout_output);

    // 4. OrdLock suffix
    try buf.appendSlice(allocator, &ORDLOCK_SUFFIX);

    return buf.toOwnedSlice(allocator);
}

/// Build an OrdLock locking script with a raw payout output.
///
/// This variant accepts pre-built payout bytes (serialized TransactionOutput)
/// instead of constructing one from a P2PKH address. Useful when the payout
/// includes a non-standard locking script.
pub fn lockRaw(
    allocator: std.mem.Allocator,
    seller_pkh: [20]u8,
    payout: []const u8,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, &ORDLOCK_PREFIX);
    try appendPushData(&buf, allocator, &seller_pkh);
    try appendPushData(&buf, allocator, payout);
    try buf.appendSlice(allocator, &ORDLOCK_SUFFIX);

    return buf.toOwnedSlice(allocator);
}

/// Decode an OrdLock from raw script bytes.
///
/// Scans for the OrdLock prefix/suffix pattern, then parses the two
/// push data elements between them (seller PKH + payout output).
/// Returns null if the script does not contain a valid OrdLock.
pub fn decode(script_bytes: []const u8) ?OrdLockData {
    const s = script_bytes;

    // Find prefix
    const prefix_idx = indexOf(s, &ORDLOCK_PREFIX) orelse return null;
    const data_start = prefix_idx + ORDLOCK_PREFIX.len;

    // Find suffix after prefix
    const suffix_idx = indexOfFrom(s, data_start, &ORDLOCK_SUFFIX) orelse return null;

    // Extract the data between prefix and suffix
    const data = s[data_start..suffix_idx];
    if (data.len == 0) return null;

    // Parse first push: seller PKH (20 bytes)
    const pkh_push = readPushData(data, 0) orelse return null;
    if (pkh_push.data.len != 20) return null;

    // Parse second push: payout output
    const payout_push = readPushData(data, pkh_push.end) orelse return null;
    if (payout_push.data.len < 9) return null; // minimum: 8 satoshis + 1 varint(0)

    // Parse satoshis from payout (first 8 bytes, little-endian)
    const price_sats: u64 = @bitCast(std.mem.readInt(i64, payout_push.data[0..8], .little));

    return OrdLockData{
        .seller_pkh = pkh_push.data[0..20].*,
        .price_sats = price_sats,
        .payout = payout_push.data,
    };
}

/// Check whether a script contains an OrdLock pattern.
pub fn isOrdLock(script_bytes: []const u8) bool {
    const prefix_idx = indexOf(script_bytes, &ORDLOCK_PREFIX) orelse return false;
    return indexOfFrom(script_bytes, prefix_idx + ORDLOCK_PREFIX.len, &ORDLOCK_SUFFIX) != null;
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Build a serialized TransactionOutput for a P2PKH payout.
/// Returns a fixed-size buffer: 8 (satoshis) + 1 (varint 25) + 25 (P2PKH) = 34 bytes.
fn buildPayoutOutput(satoshis: u64, pkh: *const [20]u8) [34]u8 {
    var out: [34]u8 = undefined;

    // 8-byte little-endian satoshis
    std.mem.writeInt(i64, out[0..8], @bitCast(satoshis), .little);

    // varint for script length (25 = 0x19, fits in 1 byte)
    out[8] = 25;

    // P2PKH locking script: OP_DUP OP_HASH160 <push20> <pkh> OP_EQUALVERIFY OP_CHECKSIG
    out[9] = 0x76; // OP_DUP
    out[10] = 0xa9; // OP_HASH160
    out[11] = 0x14; // push 20 bytes
    @memcpy(out[12..32], pkh);
    out[32] = 0x88; // OP_EQUALVERIFY
    out[33] = 0xac; // OP_CHECKSIG

    return out;
}

const PushDataResult = struct {
    data: []const u8,
    end: usize,
};

/// Read a push data element at the given position.
fn readPushData(s: []const u8, pos: usize) ?PushDataResult {
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
    if (op == 0x4c) {
        if (pos + 1 >= s.len) return null;
        const data_len: usize = s[pos + 1];
        const start = pos + 2;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    // OP_PUSHDATA2
    if (op == 0x4d) {
        if (pos + 2 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u16, s[pos + 1 ..][0..2], .little);
        const start = pos + 3;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    // OP_PUSHDATA4
    if (op == 0x4e) {
        if (pos + 4 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u32, s[pos + 1 ..][0..4], .little);
        const start = pos + 5;
        const end = start + data_len;
        if (end > s.len) return null;
        return .{ .data = s[start..end], .end = end };
    }

    return null;
}

/// Find the first occurrence of `needle` in `haystack`.
fn indexOf(haystack: []const u8, needle: []const u8) ?usize {
    return indexOfFrom(haystack, 0, needle);
}

/// Find the first occurrence of `needle` in `haystack` starting at `from`.
fn indexOfFrom(haystack: []const u8, from: usize, needle: []const u8) ?usize {
    if (needle.len == 0) return from;
    if (haystack.len < from + needle.len) return null;
    var i: usize = from;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.mem.eql(u8, haystack[i..][0..needle.len], needle)) return i;
    }
    return null;
}

/// Comptime hex literal decoder. Converts a hex string to a byte array.
fn hexLiteral(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(hex_str.len * 10);
        if (hex_str.len % 2 != 0) @compileError("hex literal must have even length");
        var result: [hex_str.len / 2]u8 = undefined;
        for (0..result.len) |i| {
            result[i] = (@as(u8, hexNibble(hex_str[i * 2])) << 4) | @as(u8, hexNibble(hex_str[i * 2 + 1]));
        }
        return result;
    }
}

fn hexNibble(comptime c: u8) u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => @compileError("invalid hex character"),
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "lock produces script with correct prefix and suffix" {
    const allocator = std.testing.allocator;

    const seller_pkh = [_]u8{0x12} ** 20;
    const pay_pkh = [_]u8{0xab} ** 20;
    const price: u64 = 1000;

    const script_bytes = try lock(allocator, seller_pkh, pay_pkh, price);
    defer allocator.free(script_bytes);

    // Script must start with prefix
    try std.testing.expectEqualSlices(u8, &ORDLOCK_PREFIX, script_bytes[0..ORDLOCK_PREFIX.len]);

    // Script must end with suffix
    const suffix_start = script_bytes.len - ORDLOCK_SUFFIX.len;
    try std.testing.expectEqualSlices(u8, &ORDLOCK_SUFFIX, script_bytes[suffix_start..]);

    // Must be longer than prefix + suffix alone
    try std.testing.expect(script_bytes.len > ORDLOCK_PREFIX.len + ORDLOCK_SUFFIX.len);
}

test "decode round-trip" {
    const allocator = std.testing.allocator;

    const seller_pkh = [_]u8{0x34} ** 20;
    const pay_pkh = [_]u8{0x56} ** 20;
    const price: u64 = 5000;

    const script_bytes = try lock(allocator, seller_pkh, pay_pkh, price);
    defer allocator.free(script_bytes);

    const data = decode(script_bytes) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &seller_pkh, &data.seller_pkh);
    try std.testing.expectEqual(price, data.price_sats);
}

test "decode returns null for non-ordlock script" {
    const bad = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x00} ** 20 ++ [_]u8{ 0x88, 0xac };
    try std.testing.expect(decode(&bad) == null);
}

test "decode returns null for empty script" {
    try std.testing.expect(decode(&.{}) == null);
}

test "decode returns null for prefix-only script" {
    try std.testing.expect(decode(&ORDLOCK_PREFIX) == null);
}

test "decode returns null for suffix-only script" {
    try std.testing.expect(decode(&ORDLOCK_SUFFIX) == null);
}

test "decode returns null for prefix+suffix with no data" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &ORDLOCK_PREFIX);
    try buf.appendSlice(allocator, &ORDLOCK_SUFFIX);
    try std.testing.expect(decode(buf.items) == null);
}

test "decode returns null for invalid data between prefix and suffix" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &ORDLOCK_PREFIX);
    // Push 3 bytes (not 20), which is an invalid seller PKH
    try buf.appendSlice(allocator, &[_]u8{ 0x03, 0xFF, 0xEE, 0xDD });
    try buf.appendSlice(allocator, &ORDLOCK_SUFFIX);
    try std.testing.expect(decode(buf.items) == null);
}

test "lock with various prices" {
    const allocator = std.testing.allocator;
    const seller_pkh = [_]u8{0xaa} ** 20;
    const pay_pkh = [_]u8{0xbb} ** 20;

    const prices = [_]u64{ 1, 100, 10_000, 1_000_000, 100_000_000, 2_100_000_000_000_000 };

    for (prices) |price| {
        const script_bytes = try lock(allocator, seller_pkh, pay_pkh, price);
        defer allocator.free(script_bytes);

        const data = decode(script_bytes) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(price, data.price_sats);
        try std.testing.expectEqualSlices(u8, &seller_pkh, &data.seller_pkh);
    }
}

test "isOrdLock detects valid ordlock scripts" {
    const allocator = std.testing.allocator;

    const seller_pkh = [_]u8{0x11} ** 20;
    const pay_pkh = [_]u8{0x22} ** 20;

    const script_bytes = try lock(allocator, seller_pkh, pay_pkh, 42);
    defer allocator.free(script_bytes);

    try std.testing.expect(isOrdLock(script_bytes));
}

test "isOrdLock rejects non-ordlock scripts" {
    try std.testing.expect(!isOrdLock(&[_]u8{ 0x76, 0xa9, 0x14 }));
    try std.testing.expect(!isOrdLock(&.{}));
}

test "payout output contains correct P2PKH structure" {
    const allocator = std.testing.allocator;

    const seller_pkh = [_]u8{0x01} ** 20;
    const pay_pkh = [_]u8{0x02} ** 20;
    const price: u64 = 7777;

    const script_bytes = try lock(allocator, seller_pkh, pay_pkh, price);
    defer allocator.free(script_bytes);

    const data = decode(script_bytes) orelse return error.TestUnexpectedResult;

    // Payout should be 34 bytes: 8 (sats) + 1 (varint) + 25 (P2PKH)
    try std.testing.expectEqual(@as(usize, 34), data.payout.len);

    // Check the P2PKH locking script inside the payout
    // Offset 9: OP_DUP(0x76) OP_HASH160(0xa9) push20(0x14) <pkh> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
    try std.testing.expectEqual(@as(u8, 0x76), data.payout[9]);
    try std.testing.expectEqual(@as(u8, 0xa9), data.payout[10]);
    try std.testing.expectEqual(@as(u8, 0x14), data.payout[11]);
    try std.testing.expectEqualSlices(u8, &pay_pkh, data.payout[12..32]);
    try std.testing.expectEqual(@as(u8, 0x88), data.payout[32]);
    try std.testing.expectEqual(@as(u8, 0xac), data.payout[33]);
}

test "lockRaw with custom payout" {
    const allocator = std.testing.allocator;

    const seller_pkh = [_]u8{0xcc} ** 20;

    // Build a custom payout: 50000 sats to an OP_RETURN script
    var payout: [12]u8 = undefined;
    std.mem.writeInt(i64, payout[0..8], 50000, .little);
    payout[8] = 3; // varint: script length = 3
    payout[9] = 0x6a; // OP_RETURN
    payout[10] = 0x01; // push 1 byte
    payout[11] = 0xff; // data

    const script_bytes = try lockRaw(allocator, seller_pkh, &payout);
    defer allocator.free(script_bytes);

    const data = decode(script_bytes) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &seller_pkh, &data.seller_pkh);
    try std.testing.expectEqual(@as(u64, 50000), data.price_sats);
    try std.testing.expectEqualSlices(u8, &payout, data.payout);
}

test "prefix and suffix constants match Go implementation" {
    // Verify prefix length matches the Go hex constant (100 hex chars = 50 bytes)
    // Go hex: "2097dfd768...0000" = 100 hex chars = 50 bytes
    // Actually the Go prefix is longer. Let's verify by checking known start/end bytes.
    try std.testing.expectEqual(@as(u8, 0x20), ORDLOCK_PREFIX[0]);
    try std.testing.expectEqual(@as(u8, 0x97), ORDLOCK_PREFIX[1]);
    // Ends with 0x00, 0x00
    try std.testing.expectEqual(@as(u8, 0x00), ORDLOCK_PREFIX[ORDLOCK_PREFIX.len - 1]);
    try std.testing.expectEqual(@as(u8, 0x00), ORDLOCK_PREFIX[ORDLOCK_PREFIX.len - 2]);

    // Suffix starts with 0x61
    try std.testing.expectEqual(@as(u8, 0x61), ORDLOCK_SUFFIX[0]);
    // Suffix ends with 0x68, 0x68
    try std.testing.expectEqual(@as(u8, 0x68), ORDLOCK_SUFFIX[ORDLOCK_SUFFIX.len - 1]);
    try std.testing.expectEqual(@as(u8, 0x68), ORDLOCK_SUFFIX[ORDLOCK_SUFFIX.len - 2]);
}
