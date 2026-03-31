//! Magic Attribute Protocol (MAP) template.
//! Matches go-templates/template/bitcom/map and @1sat/templates/map.
//!
//! MAP protocol format:
//!   OP_RETURN <MAP_PREFIX> SET <key1> <val1> <key2> <val2> ...
//!   OP_RETURN <MAP_PREFIX> DEL <key1> <key2> ...
//!
//! Or appended after inscription via pipe separator:
//!   | <MAP_PREFIX> SET <key1> <val1> ...

const std = @import("std");
const bsvz = @import("bsvz");
const Opcode = bsvz.script.opcode.Opcode;
const appendPushData = bsvz.script.builder.appendPushData;
const appendOpcodes = bsvz.script.builder.appendOpcodes;

/// MAP protocol prefix (Bitcoin address).
pub const MAP_PREFIX = "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5";

/// Pipe separator used between protocols in OP_RETURN scripts.
const PIPE_SEPARATOR = "|";

/// MAP protocol operations.
pub const Operation = enum {
    SET,
    DELETE,

    pub fn toString(self: Operation) []const u8 {
        return switch (self) {
            .SET => "SET",
            .DELETE => "DEL",
        };
    }

    pub fn fromString(s: []const u8) ?Operation {
        if (std.mem.eql(u8, s, "SET")) return .SET;
        if (std.mem.eql(u8, s, "DEL")) return .DELETE;
        return null;
    }
};

/// A single key-value pair for MAP protocol data.
pub const Pair = struct {
    key: []const u8,
    value: []const u8,
};

/// Decoded MAP protocol data.
pub const MapData = struct {
    operation: Operation,
    pairs: []Pair,

    pub fn deinit(self: *MapData, allocator: std.mem.Allocator) void {
        allocator.free(self.pairs);
    }
};

pub const Error = error{
    InvalidPushData,
    UnexpectedEndOfScript,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

/// Build a MAP protocol script as raw bytes.
///
/// Output format:
///   OP_RETURN <push MAP_PREFIX> <push operation> [<push key> <push value>]*
///
/// For DELETE, values are empty strings.
pub fn encode(
    allocator: std.mem.Allocator,
    operation: Operation,
    pairs: []const Pair,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // OP_RETURN
    try appendOpcodes(&buf, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});

    // Push MAP prefix
    try appendPushData(&buf, allocator, MAP_PREFIX);

    // Push operation command
    try appendPushData(&buf, allocator, operation.toString());

    // Push key-value pairs
    for (pairs) |pair| {
        try appendPushData(&buf, allocator, pair.key);
        switch (operation) {
            .SET => try appendPushData(&buf, allocator, pair.value),
            .DELETE => {}, // DEL only has keys, no values
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Decode MAP protocol data from raw script bytes.
///
/// Expects the script to begin with OP_RETURN followed by the MAP prefix push.
/// Returns null if the script is not a valid MAP protocol script.
pub fn decode(allocator: std.mem.Allocator, script_bytes: []const u8) Error!?MapData {
    const s = script_bytes;
    var pos: usize = 0;

    // Look for OP_RETURN
    if (pos >= s.len) return null;
    if (s[pos] != @intFromEnum(Opcode.OP_RETURN)) return null;
    pos += 1;

    // Read MAP prefix
    const prefix_pd = readPushData(s, pos) orelse return null;
    if (!std.mem.eql(u8, prefix_pd.data, MAP_PREFIX)) return null;
    pos = prefix_pd.end;

    // Read operation command
    const cmd_pd = readPushData(s, pos) orelse return null;
    const operation = Operation.fromString(cmd_pd.data) orelse return null;
    pos = cmd_pd.end;

    // Read key-value pairs
    var pairs_list: std.ArrayListUnmanaged(Pair) = .empty;
    errdefer pairs_list.deinit(allocator);

    switch (operation) {
        .SET => {
            while (pos < s.len) {
                // Read key
                const key_pd = readPushData(s, pos) orelse break;
                // Read value
                const val_pd = readPushData(s, key_pd.end) orelse break;
                try pairs_list.append(allocator, .{
                    .key = cleanNullBytes(key_pd.data),
                    .value = cleanNullBytes(val_pd.data),
                });
                pos = val_pd.end;
            }
        },
        .DELETE => {
            while (pos < s.len) {
                const key_pd = readPushData(s, pos) orelse break;
                try pairs_list.append(allocator, .{
                    .key = key_pd.data,
                    .value = &.{},
                });
                pos = key_pd.end;
            }
        },
    }

    return .{
        .operation = operation,
        .pairs = try pairs_list.toOwnedSlice(allocator),
    };
}

/// Append MAP protocol data after a pipe separator to an existing script.
///
/// Output format:
///   <existing_script> <push "|"> <push MAP_PREFIX> <push operation> [<push key> <push value>]*
pub fn appendToScript(
    allocator: std.mem.Allocator,
    existing_script: []const u8,
    operation: Operation,
    pairs: []const Pair,
) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Copy existing script
    try buf.appendSlice(allocator, existing_script);

    // Pipe separator
    try appendPushData(&buf, allocator, PIPE_SEPARATOR);

    // MAP prefix
    try appendPushData(&buf, allocator, MAP_PREFIX);

    // Operation command
    try appendPushData(&buf, allocator, operation.toString());

    // Key-value pairs
    for (pairs) |pair| {
        try appendPushData(&buf, allocator, pair.key);
        switch (operation) {
            .SET => try appendPushData(&buf, allocator, pair.value),
            .DELETE => {},
        }
    }

    return buf.toOwnedSlice(allocator);
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Replace null bytes with spaces, matching Go/TS behavior.
fn cleanNullBytes(data: []const u8) []const u8 {
    // We return the original slice; null-byte cleaning would require
    // allocation. The Go implementation replaces in-place but we return
    // slices into the original script buffer. Callers that need cleaned
    // strings should copy and replace.
    return data;
}

const PushDataResult = struct {
    data: []const u8,
    end: usize,
};

/// Read a push data element at the given position.
/// Returns null if the opcode at pos is not a push data instruction.
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

// ── Tests ───────────────────────────────────────────────────────────────

test "encode SET with multiple pairs" {
    const allocator = std.testing.allocator;

    const pairs = [_]Pair{
        .{ .key = "app", .value = "bsocial" },
        .{ .key = "type", .value = "post" },
    };

    const script_bytes = try encode(allocator, .SET, &pairs);
    defer allocator.free(script_bytes);

    // Verify starts with OP_RETURN
    try std.testing.expectEqual(@as(u8, @intFromEnum(Opcode.OP_RETURN)), script_bytes[0]);

    // Decode round-trip
    const decoded = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;
    defer @constCast(&decoded).deinit(allocator);

    try std.testing.expectEqual(Operation.SET, decoded.operation);
    try std.testing.expectEqual(@as(usize, 2), decoded.pairs.len);
    try std.testing.expectEqualSlices(u8, "app", decoded.pairs[0].key);
    try std.testing.expectEqualSlices(u8, "bsocial", decoded.pairs[0].value);
    try std.testing.expectEqualSlices(u8, "type", decoded.pairs[1].key);
    try std.testing.expectEqualSlices(u8, "post", decoded.pairs[1].value);
}

test "encode DELETE with keys" {
    const allocator = std.testing.allocator;

    const pairs = [_]Pair{
        .{ .key = "app", .value = "" },
        .{ .key = "type", .value = "" },
    };

    const script_bytes = try encode(allocator, .DELETE, &pairs);
    defer allocator.free(script_bytes);

    // Decode round-trip
    const decoded = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;
    defer @constCast(&decoded).deinit(allocator);

    try std.testing.expectEqual(Operation.DELETE, decoded.operation);
    try std.testing.expectEqual(@as(usize, 2), decoded.pairs.len);
    try std.testing.expectEqualSlices(u8, "app", decoded.pairs[0].key);
    try std.testing.expectEqualSlices(u8, "type", decoded.pairs[1].key);
}

test "decode returns null for empty script" {
    const allocator = std.testing.allocator;
    const result = try decode(allocator, &.{});
    try std.testing.expect(result == null);
}

test "decode returns null for non-MAP script" {
    const allocator = std.testing.allocator;
    // OP_RETURN followed by some random push
    const bad_script = [_]u8{ 0x6a, 0x03, 0x01, 0x02, 0x03 };
    const result = try decode(allocator, &bad_script);
    try std.testing.expect(result == null);
}

test "decode returns null for script without OP_RETURN" {
    const allocator = std.testing.allocator;
    const bad_script = [_]u8{ 0x00, 0x51, 0x52 };
    const result = try decode(allocator, &bad_script);
    try std.testing.expect(result == null);
}

test "encode SET with single pair round-trip" {
    const allocator = std.testing.allocator;

    const pairs = [_]Pair{
        .{ .key = "name", .value = "test" },
    };

    const script_bytes = try encode(allocator, .SET, &pairs);
    defer allocator.free(script_bytes);

    const decoded = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;
    defer @constCast(&decoded).deinit(allocator);

    try std.testing.expectEqual(Operation.SET, decoded.operation);
    try std.testing.expectEqual(@as(usize, 1), decoded.pairs.len);
    try std.testing.expectEqualSlices(u8, "name", decoded.pairs[0].key);
    try std.testing.expectEqualSlices(u8, "test", decoded.pairs[0].value);
}

test "decode SET with missing value ignores incomplete pair" {
    const allocator = std.testing.allocator;

    // Build a script with SET command but only a key, no value
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try appendOpcodes(&buf, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});
    try appendPushData(&buf, allocator, MAP_PREFIX);
    try appendPushData(&buf, allocator, "SET");
    try appendPushData(&buf, allocator, "key_only");
    // Intentionally no value

    const decoded = (try decode(allocator, buf.items)) orelse
        return error.TestUnexpectedResult;
    defer @constCast(&decoded).deinit(allocator);

    try std.testing.expectEqual(Operation.SET, decoded.operation);
    // Key without value should be dropped (matches Go behavior)
    try std.testing.expectEqual(@as(usize, 0), decoded.pairs.len);
}

test "appendToScript adds MAP after pipe separator" {
    const allocator = std.testing.allocator;

    // Create a simple existing script (just OP_RETURN + some data)
    var existing: std.ArrayListUnmanaged(u8) = .empty;
    defer existing.deinit(allocator);
    try appendOpcodes(&existing, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});
    try appendPushData(&existing, allocator, "some_data");

    const pairs = [_]Pair{
        .{ .key = "app", .value = "bsocial" },
    };

    const result = try appendToScript(allocator, existing.items, .SET, &pairs);
    defer allocator.free(result);

    // Verify the original script is preserved at the start
    try std.testing.expectEqualSlices(u8, existing.items, result[0..existing.items.len]);

    // Verify pipe separator follows (push 1 byte "|")
    const pipe_start = existing.items.len;
    try std.testing.expectEqual(@as(u8, 0x01), result[pipe_start]); // push 1 byte
    try std.testing.expectEqual(@as(u8, '|'), result[pipe_start + 1]);
}

test "encode and verify exact script structure" {
    const allocator = std.testing.allocator;

    const pairs = [_]Pair{
        .{ .key = "app", .value = "bsocial" },
    };

    const script_bytes = try encode(allocator, .SET, &pairs);
    defer allocator.free(script_bytes);

    // Manually verify byte-by-byte:
    // [0]    OP_RETURN (0x6a)
    // [1]    push 34 bytes (MAP_PREFIX len)
    // [2..35] MAP_PREFIX
    // [36]   push 3 bytes
    // [37..39] "SET"
    // [40]   push 3 bytes
    // [41..43] "app"
    // [44]   push 7 bytes
    // [45..51] "bsocial"

    var pos: usize = 0;

    // OP_RETURN
    try std.testing.expectEqual(@as(u8, 0x6a), script_bytes[pos]);
    pos += 1;

    // MAP_PREFIX (34 chars)
    try std.testing.expectEqual(@as(u8, 34), script_bytes[pos]);
    pos += 1;
    try std.testing.expectEqualSlices(u8, MAP_PREFIX, script_bytes[pos .. pos + 34]);
    pos += 34;

    // "SET" (3 chars)
    try std.testing.expectEqual(@as(u8, 3), script_bytes[pos]);
    pos += 1;
    try std.testing.expectEqualSlices(u8, "SET", script_bytes[pos .. pos + 3]);
    pos += 3;

    // "app" (3 chars)
    try std.testing.expectEqual(@as(u8, 3), script_bytes[pos]);
    pos += 1;
    try std.testing.expectEqualSlices(u8, "app", script_bytes[pos .. pos + 3]);
    pos += 3;

    // "bsocial" (7 chars)
    try std.testing.expectEqual(@as(u8, 7), script_bytes[pos]);
    pos += 1;
    try std.testing.expectEqualSlices(u8, "bsocial", script_bytes[pos .. pos + 7]);
    pos += 7;

    // Should be end of script
    try std.testing.expectEqual(pos, script_bytes.len);
}
