//! BSV-21 fungible token template.
//! Matches go-templates/template/bsv21 and @1sat/templates/bsv21.
//!
//! BSV-21 is the fungible token standard on BSV. Tokens are inscriptions with
//! JSON content (MIME type `application/bsv-20`) carrying protocol fields:
//!
//!   {"p":"bsv-20","op":"deploy+mint","sym":"TOKEN","dec":"8","amt":"21000000"}
//!   {"p":"bsv-20","op":"transfer","id":"<txid>_<vout>","amt":"500"}
//!   {"p":"bsv-20","op":"burn","id":"<txid>_<vout>","amt":"100"}
//!
//! The JSON payload is wrapped in an inscription envelope via the inscription
//! template.

const std = @import("std");
const inscription = @import("inscription.zig");

/// MIME type for BSV-20 / BSV-21 token inscriptions.
const CONTENT_TYPE = "application/bsv-20";

/// Maximum symbol length.
const MAX_SYMBOL_LEN = 32;

/// Maximum decimal places.
const MAX_DECIMALS: u8 = 18;

/// Token operation types.
pub const Operation = enum {
    deploy_mint,
    transfer,
    burn,

    pub fn toString(self: Operation) []const u8 {
        return switch (self) {
            .deploy_mint => "deploy+mint",
            .transfer => "transfer",
            .burn => "burn",
        };
    }

    pub fn fromString(s: []const u8) ?Operation {
        if (std.mem.eql(u8, s, "deploy+mint")) return .deploy_mint;
        if (std.mem.eql(u8, s, "transfer")) return .transfer;
        if (std.mem.eql(u8, s, "burn")) return .burn;
        return null;
    }
};

/// Decoded BSV-21 token data.
pub const Bsv21Token = struct {
    /// Token operation.
    op: Operation,
    /// Token amount (unsigned integer, string-encoded in JSON).
    amt: u64,
    /// Token symbol (deploy+mint only).
    symbol: ?[]const u8 = null,
    /// Decimal places, 0-18 (deploy+mint only).
    decimals: ?u8 = null,
    /// Icon outpoint or URI (deploy+mint only).
    icon: ?[]const u8 = null,
    /// Token ID in `txid_vout` format (transfer/burn only).
    id: ?[]const u8 = null,
};

pub const Error = error{
    EmptySymbol,
    SymbolTooLong,
    ZeroAmount,
    InvalidDecimals,
    EmptyTokenId,
    InvalidTokenIdFormat,
} || inscription.Error;

/// Build a deploy+mint inscription as raw script bytes.
///
/// Creates a new token with the given symbol, max supply, and optional
/// decimals and icon. Returns the inscription envelope bytes.
pub fn deploy(
    allocator: std.mem.Allocator,
    symbol: []const u8,
    decimals: ?u8,
    max_supply: u64,
    icon_id: ?[]const u8,
) Error![]u8 {
    if (symbol.len == 0) return Error.EmptySymbol;
    if (symbol.len > MAX_SYMBOL_LEN) return Error.SymbolTooLong;
    if (max_supply == 0) return Error.ZeroAmount;
    if (decimals) |d| {
        if (d > MAX_DECIMALS) return Error.InvalidDecimals;
    }

    const json = try buildDeployJson(allocator, symbol, decimals, max_supply, icon_id);
    defer allocator.free(json);

    return inscription.create(allocator, json, CONTENT_TYPE, .{});
}

/// Build a transfer inscription as raw script bytes.
///
/// Transfers `amount` tokens identified by `token_id` (format: `txid_vout`).
pub fn transfer(
    allocator: std.mem.Allocator,
    token_id: []const u8,
    amount: u64,
) Error![]u8 {
    try validateTokenId(token_id);
    if (amount == 0) return Error.ZeroAmount;

    const json = try buildTransferBurnJson(allocator, "transfer", token_id, amount);
    defer allocator.free(json);

    return inscription.create(allocator, json, CONTENT_TYPE, .{});
}

/// Build a burn inscription as raw script bytes.
///
/// Burns `amount` tokens identified by `token_id` (format: `txid_vout`).
pub fn burn(
    allocator: std.mem.Allocator,
    token_id: []const u8,
    amount: u64,
) Error![]u8 {
    try validateTokenId(token_id);
    if (amount == 0) return Error.ZeroAmount;

    const json = try buildTransferBurnJson(allocator, "burn", token_id, amount);
    defer allocator.free(json);

    return inscription.create(allocator, json, CONTENT_TYPE, .{});
}

/// Decode a BSV-21 token from raw inscription script bytes.
///
/// Returns null if the script does not contain a valid BSV-21 inscription.
pub fn decode(allocator: std.mem.Allocator, script_bytes: []const u8) Error!?Bsv21Token {
    const insc = (try inscription.decode(allocator, script_bytes)) orelse return null;

    // Must be application/bsv-20
    if (!std.mem.eql(u8, insc.content_type, CONTENT_TYPE)) return null;

    // Parse JSON content
    return parseTokenJson(insc.content);
}

// ── JSON construction helpers ────────────────────────────────────────

/// Build the JSON payload for a deploy+mint operation.
fn buildDeployJson(
    allocator: std.mem.Allocator,
    symbol: []const u8,
    decimals: ?u8,
    amount: u64,
    icon_id: ?[]const u8,
) std.mem.Allocator.Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"sym\":\"");
    try writeJsonEscaped(w, symbol);
    try w.writeAll("\",\"amt\":\"");
    try w.print("{d}", .{amount});
    try w.writeByte('"');

    if (decimals) |d| {
        try w.writeAll(",\"dec\":\"");
        try w.print("{d}", .{d});
        try w.writeByte('"');
    }

    if (icon_id) |ic| {
        if (ic.len > 0) {
            try w.writeAll(",\"icon\":\"");
            try writeJsonEscaped(w, ic);
            try w.writeByte('"');
        }
    }

    try w.writeByte('}');
    return buf.toOwnedSlice(allocator);
}

/// Build the JSON payload for a transfer or burn operation.
fn buildTransferBurnJson(
    allocator: std.mem.Allocator,
    op: []const u8,
    token_id: []const u8,
    amount: u64,
) std.mem.Allocator.Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{\"p\":\"bsv-20\",\"op\":\"");
    try w.writeAll(op);
    try w.writeAll("\",\"id\":\"");
    try writeJsonEscaped(w, token_id);
    try w.writeAll("\",\"amt\":\"");
    try w.print("{d}", .{amount});
    try w.writeAll("\"}");

    return buf.toOwnedSlice(allocator);
}

/// Escape a string for JSON output (handles `"`, `\`, and control characters).
fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

// ── JSON parsing helpers ─────────────────────────────────────────────

/// Parse a BSV-21 token from JSON content bytes.
///
/// Returns slices that point directly into `content`, so the returned
/// Bsv21Token is valid as long as the underlying script bytes are alive.
/// No allocations are performed.
fn parseTokenJson(content: []const u8) ?Bsv21Token {
    // Validate protocol: "p":"bsv-20"
    const p_val = jsonStringValue(content, "p") orelse return null;
    if (!std.mem.eql(u8, p_val, "bsv-20")) return null;

    // Parse operation
    const op_str = jsonStringValue(content, "op") orelse return null;
    const op = Operation.fromString(op_str) orelse return null;

    // Parse amount (must be a string value)
    const amt_str = jsonStringValue(content, "amt") orelse return null;
    const amt = std.fmt.parseUnsigned(u64, amt_str, 10) catch return null;
    if (amt == 0) return null;

    var token = Bsv21Token{
        .op = op,
        .amt = amt,
    };

    switch (op) {
        .deploy_mint => {
            // Symbol is required
            const sym = jsonStringValue(content, "sym") orelse return null;
            if (sym.len == 0 or sym.len > MAX_SYMBOL_LEN) return null;
            token.symbol = sym;

            // Decimals are optional (string in JSON)
            if (jsonStringValue(content, "dec")) |dec_str| {
                const d = std.fmt.parseUnsigned(u8, dec_str, 10) catch return null;
                if (d > MAX_DECIMALS) return null;
                token.decimals = d;
            }

            // Icon is optional
            if (jsonStringValue(content, "icon")) |icon_str| {
                if (icon_str.len > 0) {
                    token.icon = icon_str;
                }
            }
        },
        .transfer, .burn => {
            // Token ID is required
            const id = jsonStringValue(content, "id") orelse return null;
            if (!isValidTokenId(id)) return null;
            token.id = id;
        },
    }

    return token;
}

/// Extract the string value for a given key from a flat JSON object.
///
/// Searches for `"key":"value"` and returns a slice of `value` within
/// the source bytes. Only handles simple unescaped string values (which
/// is sufficient for BSV-21 fields). Returns null if the key is not found.
fn jsonStringValue(json: []const u8, key: []const u8) ?[]const u8 {
    // Build the search needle: "key":"
    // We scan for this exact byte pattern in the JSON.
    var pos: usize = 0;
    while (pos < json.len) {
        // Find next occurrence of the key preceded by a quote
        const needle_start = std.mem.indexOf(u8, json[pos..], "\"") orelse return null;
        const abs_start = pos + needle_start + 1; // skip opening quote

        // Check if this is our key
        if (abs_start + key.len + 1 >= json.len) return null;
        if (std.mem.eql(u8, json[abs_start .. abs_start + key.len], key) and
            json[abs_start + key.len] == '"')
        {
            // Found the key. Now find the value after ":"
            var vpos = abs_start + key.len + 1; // past closing quote of key
            // Skip colon and any whitespace
            while (vpos < json.len and (json[vpos] == ':' or json[vpos] == ' ')) {
                vpos += 1;
            }
            if (vpos >= json.len or json[vpos] != '"') return null;
            vpos += 1; // skip opening quote of value

            // Find closing quote of value
            const val_end = std.mem.indexOfScalar(u8, json[vpos..], '"') orelse return null;
            return json[vpos .. vpos + val_end];
        }

        // Move past this quote and continue searching
        pos = abs_start + 1;
    }
    return null;
}

/// Validate a token ID format: 64-char hex `_` digits.
fn validateTokenId(token_id: []const u8) Error!void {
    if (token_id.len == 0) return Error.EmptyTokenId;
    if (!isValidTokenId(token_id)) return Error.InvalidTokenIdFormat;
}

fn isValidTokenId(token_id: []const u8) bool {
    // Find the underscore separator
    const sep_pos = std.mem.indexOfScalar(u8, token_id, '_') orelse return false;

    // txid must be exactly 64 hex characters
    if (sep_pos != 64) return false;
    const txid_part = token_id[0..64];
    for (txid_part) |c| {
        if (!std.ascii.isHex(c)) return false;
    }

    // vout must be one or more digits
    const vout_part = token_id[65..];
    if (vout_part.len == 0) return false;
    for (vout_part) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }

    return true;
}

// ── Tests ────────────────────────────────────────────────────────────

test "deploy: basic token and verify inscription content" {
    const allocator = std.testing.allocator;

    const script_bytes = try deploy(allocator, "TOKEN", 8, 21000000, null);
    defer allocator.free(script_bytes);

    // Decode as inscription and verify content type and JSON
    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, CONTENT_TYPE, insc.content_type);

    // Verify JSON content
    const expected_json = "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"sym\":\"TOKEN\",\"amt\":\"21000000\",\"dec\":\"8\"}";
    try std.testing.expectEqualSlices(u8, expected_json, insc.content);
}

test "deploy: token with icon" {
    const allocator = std.testing.allocator;
    const icon = "df3ceacd1a4169ec7cca3037ca2714f5fcdc0bbdb88ebfd3609257faa4814809_0";

    const script_bytes = try deploy(allocator, "BUIDL", 2, 4200000000, icon);
    defer allocator.free(script_bytes);

    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, CONTENT_TYPE, insc.content_type);

    // Verify all fields present in JSON
    const content = insc.content;
    try std.testing.expect(std.mem.indexOf(u8, content, "\"sym\":\"BUIDL\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"dec\":\"2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"amt\":\"4200000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"icon\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, icon) != null);
}

test "deploy: no decimals omits dec field" {
    const allocator = std.testing.allocator;

    const script_bytes = try deploy(allocator, "SIMPLE", null, 1000, null);
    defer allocator.free(script_bytes);

    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    // dec should not appear in JSON when null
    try std.testing.expect(std.mem.indexOf(u8, insc.content, "\"dec\"") == null);
}

test "deploy: zero decimals is included" {
    const allocator = std.testing.allocator;

    const script_bytes = try deploy(allocator, "ZERO", 0, 1000, null);
    defer allocator.free(script_bytes);

    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.indexOf(u8, insc.content, "\"dec\":\"0\"") != null);
}

test "deploy: rejects empty symbol" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.EmptySymbol, deploy(allocator, "", 0, 1000, null));
}

test "deploy: rejects symbol too long" {
    const allocator = std.testing.allocator;
    const long_sym = "A" ** 33;
    try std.testing.expectError(Error.SymbolTooLong, deploy(allocator, long_sym, 0, 1000, null));
}

test "deploy: rejects zero amount" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.ZeroAmount, deploy(allocator, "T", 0, 0, null));
}

test "deploy: rejects invalid decimals" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidDecimals, deploy(allocator, "T", 19, 1000, null));
}

test "transfer: basic and verify inscription content" {
    const allocator = std.testing.allocator;
    const token_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_0";

    const script_bytes = try transfer(allocator, token_id, 500);
    defer allocator.free(script_bytes);

    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, CONTENT_TYPE, insc.content_type);

    const expected_json = "{\"p\":\"bsv-20\",\"op\":\"transfer\",\"id\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_0\",\"amt\":\"500\"}";
    try std.testing.expectEqualSlices(u8, expected_json, insc.content);
}

test "transfer: rejects empty token id" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.EmptyTokenId, transfer(allocator, "", 100));
}

test "transfer: rejects invalid token id format" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidTokenIdFormat, transfer(allocator, "not_a_valid_id", 100));
}

test "transfer: rejects zero amount" {
    const allocator = std.testing.allocator;
    const token_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_0";
    try std.testing.expectError(Error.ZeroAmount, transfer(allocator, token_id, 0));
}

test "burn: basic and verify inscription content" {
    const allocator = std.testing.allocator;
    const token_id = "1111111111111111111111111111111111111111111111111111111111111111_5";

    const script_bytes = try burn(allocator, token_id, 999);
    defer allocator.free(script_bytes);

    const insc = (try inscription.decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, CONTENT_TYPE, insc.content_type);

    const expected_json = "{\"p\":\"bsv-20\",\"op\":\"burn\",\"id\":\"1111111111111111111111111111111111111111111111111111111111111111_5\",\"amt\":\"999\"}";
    try std.testing.expectEqualSlices(u8, expected_json, insc.content);
}

test "decode: deploy+mint round-trip" {
    const allocator = std.testing.allocator;

    const script_bytes = try deploy(allocator, "BUIDL", 2, 4200000000, "df3ceacd1a4169ec7cca3037ca2714f5fcdc0bbdb88ebfd3609257faa4814809_0");
    defer allocator.free(script_bytes);

    const token = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(Operation.deploy_mint, token.op);
    try std.testing.expectEqual(@as(u64, 4200000000), token.amt);
    try std.testing.expectEqualSlices(u8, "BUIDL", token.symbol.?);
    try std.testing.expectEqual(@as(u8, 2), token.decimals.?);
    try std.testing.expectEqualSlices(u8, "df3ceacd1a4169ec7cca3037ca2714f5fcdc0bbdb88ebfd3609257faa4814809_0", token.icon.?);
    try std.testing.expect(token.id == null);
}

test "decode: deploy+mint without decimals" {
    const allocator = std.testing.allocator;

    const script_bytes = try deploy(allocator, "SIMPLE", null, 1000, null);
    defer allocator.free(script_bytes);

    const token = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(Operation.deploy_mint, token.op);
    try std.testing.expectEqual(@as(u64, 1000), token.amt);
    try std.testing.expectEqualSlices(u8, "SIMPLE", token.symbol.?);
    try std.testing.expect(token.decimals == null);
    try std.testing.expect(token.icon == null);
}

test "decode: transfer round-trip" {
    const allocator = std.testing.allocator;
    const token_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_0";

    const script_bytes = try transfer(allocator, token_id, 500);
    defer allocator.free(script_bytes);

    const token = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(Operation.transfer, token.op);
    try std.testing.expectEqual(@as(u64, 500), token.amt);
    try std.testing.expectEqualSlices(u8, token_id, token.id.?);
    try std.testing.expect(token.symbol == null);
    try std.testing.expect(token.decimals == null);
}

test "decode: burn round-trip" {
    const allocator = std.testing.allocator;
    const token_id = "1111111111111111111111111111111111111111111111111111111111111111_5";

    const script_bytes = try burn(allocator, token_id, 999);
    defer allocator.free(script_bytes);

    const token = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(Operation.burn, token.op);
    try std.testing.expectEqual(@as(u64, 999), token.amt);
    try std.testing.expectEqualSlices(u8, token_id, token.id.?);
    try std.testing.expect(token.symbol == null);
}

test "decode: returns null for non-BSV21 inscription" {
    const allocator = std.testing.allocator;

    // Create a plain text inscription (not BSV21)
    const script_bytes = try inscription.create(allocator, "hello world", "text/plain", .{});
    defer allocator.free(script_bytes);

    const result = try decode(allocator, script_bytes);
    try std.testing.expect(result == null);
}

test "decode: returns null for invalid JSON content" {
    const allocator = std.testing.allocator;

    const script_bytes = try inscription.create(allocator, "not json", CONTENT_TYPE, .{});
    defer allocator.free(script_bytes);

    const result = try decode(allocator, script_bytes);
    try std.testing.expect(result == null);
}

test "decode: returns null for wrong protocol" {
    const allocator = std.testing.allocator;

    const script_bytes = try inscription.create(allocator, "{\"p\":\"wrong\",\"op\":\"transfer\",\"id\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_0\",\"amt\":\"100\"}", CONTENT_TYPE, .{});
    defer allocator.free(script_bytes);

    const result = try decode(allocator, script_bytes);
    try std.testing.expect(result == null);
}

test "decode: returns null for empty script" {
    const allocator = std.testing.allocator;
    const result = try decode(allocator, &.{});
    try std.testing.expect(result == null);
}

test "decode: returns null for zero amount" {
    const allocator = std.testing.allocator;

    const script_bytes = try inscription.create(allocator, "{\"p\":\"bsv-20\",\"op\":\"deploy+mint\",\"sym\":\"X\",\"amt\":\"0\"}", CONTENT_TYPE, .{});
    defer allocator.free(script_bytes);

    const result = try decode(allocator, script_bytes);
    try std.testing.expect(result == null);
}

test "decode: returns null for invalid operation" {
    const allocator = std.testing.allocator;

    const script_bytes = try inscription.create(allocator, "{\"p\":\"bsv-20\",\"op\":\"invalid\",\"amt\":\"100\"}", CONTENT_TYPE, .{});
    defer allocator.free(script_bytes);

    const result = try decode(allocator, script_bytes);
    try std.testing.expect(result == null);
}

test "decode: large amount values" {
    const allocator = std.testing.allocator;

    // u64 max is 18446744073709551615
    const script_bytes = try deploy(allocator, "BIG", null, 18446744073709551615, null);
    defer allocator.free(script_bytes);

    const token = (try decode(allocator, script_bytes)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(u64, 18446744073709551615), token.amt);
}

test "decode: all valid decimal values" {
    const allocator = std.testing.allocator;

    // Test 0, 1, 8, 18 (boundaries and common values)
    const test_values = [_]u8{ 0, 1, 8, 18 };
    for (test_values) |d| {
        const script_bytes = try deploy(allocator, "DEC", d, 1000, null);
        defer allocator.free(script_bytes);

        const token = (try decode(allocator, script_bytes)) orelse
            return error.TestUnexpectedResult;

        try std.testing.expectEqual(d, token.decimals.?);
    }
}

test "token id validation: rejects short txid" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidTokenIdFormat, transfer(allocator, "abc_0", 100));
}

test "token id validation: rejects missing vout" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidTokenIdFormat, transfer(allocator, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_", 100));
}

test "token id validation: rejects non-hex txid" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidTokenIdFormat, transfer(allocator, "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg_0", 100));
}

test "token id validation: rejects non-digit vout" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidTokenIdFormat, transfer(allocator, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789_abc", 100));
}
