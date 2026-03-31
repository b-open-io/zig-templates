//! B:// data carrier protocol template.
//! Matches go-templates/template/bitcom/b and @1sat/templates/b.
//!
//! B protocol format (after OP_RETURN):
//!   <B_PREFIX> <content> <content_type> [<encoding>] [<filename>]
//!
//! Content > 520 bytes is split into multiple pushes.

const std = @import("std");
const bsvz = @import("bsvz");
const Opcode = bsvz.script.opcode.Opcode;
const appendPushData = bsvz.script.builder.appendPushData;
const appendOpcodes = bsvz.script.builder.appendOpcodes;

/// B protocol BitCom prefix address.
pub const B_PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";

/// Maximum push data size per element. Content larger than this
/// is split into multiple consecutive pushes.
const MAX_PUSH_SIZE: usize = 520;

pub const MediaType = enum {
    text_plain,
    text_markdown,
    text_html,
    image_png,
    image_jpeg,
    application_json,
    application_pdf,
    application_octet_stream,

    pub fn toBytes(self: MediaType) []const u8 {
        return switch (self) {
            .text_plain => "text/plain",
            .text_markdown => "text/markdown",
            .text_html => "text/html",
            .image_png => "image/png",
            .image_jpeg => "image/jpeg",
            .application_json => "application/json",
            .application_pdf => "application/pdf",
            .application_octet_stream => "application/octet-stream",
        };
    }
};

pub const Encoding = enum {
    utf8,
    binary,

    pub fn toBytes(self: Encoding) []const u8 {
        return switch (self) {
            .utf8 => "utf-8",
            .binary => "binary",
        };
    }
};

/// Decoded B protocol data. All slices point into the original
/// script byte buffer and must not outlive it.
pub const BData = struct {
    /// Raw content bytes.
    content: []const u8,
    /// MIME content type (e.g. "text/plain").
    content_type: []const u8,
    /// Encoding string (e.g. "utf-8", "binary").
    encoding: []const u8,
    /// Optional filename.
    filename: ?[]const u8 = null,
};

pub const Error = error{
    UnexpectedEndOfScript,
} || std.mem.Allocator.Error || bsvz.script.builder.Error;

/// Build a B:// OP_RETURN script from the given data.
///
/// Output format:
///   OP_RETURN
///   <push B_PREFIX>
///   <push content>          (split into multiple pushes if > MAX_PUSH_SIZE)
///   <push content_type>
///   <push encoding>
///   [<push filename>]
pub fn encode(allocator: std.mem.Allocator, data: BData) Error![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // OP_RETURN
    try appendOpcodes(&buf, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});

    // Push B prefix
    try appendPushData(&buf, allocator, B_PREFIX);

    // Push content, splitting into chunks if necessary
    if (data.content.len <= MAX_PUSH_SIZE) {
        try appendPushData(&buf, allocator, data.content);
    } else {
        var offset: usize = 0;
        while (offset < data.content.len) {
            const end = @min(offset + MAX_PUSH_SIZE, data.content.len);
            try appendPushData(&buf, allocator, data.content[offset..end]);
            offset = end;
        }
    }

    // Push content type
    try appendPushData(&buf, allocator, data.content_type);

    // Push encoding
    try appendPushData(&buf, allocator, data.encoding);

    // Push optional filename
    if (data.filename) |filename| {
        try appendPushData(&buf, allocator, filename);
    }

    return buf.toOwnedSlice(allocator);
}

/// Decode a B:// script from raw bytes.
///
/// Scans for OP_RETURN followed by the B prefix push, then reads
/// content, content_type, encoding, and optional filename pushes.
/// Returns null if the script is not a valid B:// protocol script.
///
/// When content was split across multiple pushes during encoding,
/// they are reassembled into a single contiguous allocation.
pub fn decode(allocator: std.mem.Allocator, script_bytes: []const u8) Error!?BData {
    const s = script_bytes;
    if (s.len < 2) return null;

    // Find OP_RETURN
    var pos: usize = 0;
    while (pos < s.len) {
        if (s[pos] == @intFromEnum(Opcode.OP_RETURN)) {
            pos += 1;
            break;
        }
        pos = skipOp(s, pos) orelse return null;
    }
    if (pos >= s.len) return null;

    // Read B prefix
    const prefix_pd = readPushData(s, pos) orelse return null;
    if (!std.mem.eql(u8, prefix_pd.data, B_PREFIX)) return null;
    pos = prefix_pd.end;

    // Read content push(es). After reading the first push, peek ahead:
    // if the next push looks like a MIME type (contains '/'), then the
    // first push was the complete content. Otherwise, accumulate pushes
    // until we find a MIME-type push — that marks the start of content_type.
    var content_parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer content_parts.deinit(allocator);

    // Read the first content push
    const first_pd = readPushData(s, pos) orelse return null;
    try content_parts.append(allocator, first_pd.data);
    pos = first_pd.end;

    // Accumulate additional content pushes until the next push is a MIME type
    while (pos < s.len) {
        const peek_pd = readPushData(s, pos) orelse break;
        if (looksLikeMimeType(peek_pd.data)) break;
        try content_parts.append(allocator, peek_pd.data);
        pos = peek_pd.end;
    }

    // Resolve content: if single chunk, use the slice directly (zero-copy).
    // If multiple chunks, allocate and concatenate.
    var content: []const u8 = undefined;
    var owned_content: ?[]u8 = null;
    if (content_parts.items.len == 1) {
        content = content_parts.items[0];
    } else {
        var total: usize = 0;
        for (content_parts.items) |part| total += part.len;
        const merged = try allocator.alloc(u8, total);
        var off: usize = 0;
        for (content_parts.items) |part| {
            @memcpy(merged[off..][0..part.len], part);
            off += part.len;
        }
        content = merged;
        owned_content = merged;
    }
    errdefer if (owned_content) |oc| allocator.free(oc);

    // Read content_type
    const ct_pd = readPushData(s, pos) orelse return null;
    pos = ct_pd.end;

    // Read encoding
    const enc_pd = readPushData(s, pos) orelse return null;
    pos = enc_pd.end;

    // Optional filename
    var filename: ?[]const u8 = null;
    if (pos < s.len) {
        if (readPushData(s, pos)) |fn_pd| {
            filename = fn_pd.data;
        }
    }

    return BData{
        .content = content,
        .content_type = ct_pd.data,
        .encoding = enc_pd.data,
        .filename = filename,
    };
}

/// Check if a byte slice looks like a MIME type (contains '/' and is
/// printable ASCII). Used to distinguish content pushes from the
/// content_type push during decode.
fn looksLikeMimeType(data: []const u8) bool {
    if (data.len == 0 or data.len > 255) return false;
    var has_slash = false;
    for (data) |byte| {
        if (byte == '/') {
            has_slash = true;
        } else if (byte < 0x20 or byte > 0x7e) {
            return false;
        }
    }
    return has_slash;
}

// ── Push data reading / op skipping (shared with inscription.zig) ──

const PushDataResult = struct {
    data: []const u8,
    end: usize,
};

fn readPushData(s: []const u8, pos: usize) ?PushDataResult {
    if (pos >= s.len) return null;
    const op = s[pos];

    // OP_0 — empty push
    if (op == @intFromEnum(Opcode.OP_0)) {
        return .{ .data = s[pos..pos], .end = pos + 1 };
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

fn skipOp(s: []const u8, pos: usize) ?usize {
    if (pos >= s.len) return null;
    const op = s[pos];

    if (op >= 0x01 and op <= 0x4b) {
        const end = pos + 1 + @as(usize, op);
        return if (end <= s.len) end else null;
    }
    if (op == @intFromEnum(Opcode.OP_PUSHDATA1)) {
        if (pos + 1 >= s.len) return null;
        const data_len: usize = s[pos + 1];
        const end = pos + 2 + data_len;
        return if (end <= s.len) end else null;
    }
    if (op == @intFromEnum(Opcode.OP_PUSHDATA2)) {
        if (pos + 2 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u16, s[pos + 1 ..][0..2], .little);
        const end = pos + 3 + data_len;
        return if (end <= s.len) end else null;
    }
    if (op == @intFromEnum(Opcode.OP_PUSHDATA4)) {
        if (pos + 4 >= s.len) return null;
        const data_len: usize = std.mem.readInt(u32, s[pos + 1 ..][0..4], .little);
        const end = pos + 5 + data_len;
        return if (end <= s.len) end else null;
    }

    return pos + 1;
}

// ── Tests ────────────────────────────────────────────────────────────

test "encode basic text/plain B:// script" {
    const allocator = std.testing.allocator;
    const data = BData{
        .content = "Hello World",
        .content_type = "text/plain",
        .encoding = "utf-8",
    };

    const script = try encode(allocator, data);
    defer allocator.free(script);

    // OP_RETURN (1) + push B_PREFIX (1+34) + push content (1+11) +
    // push content_type (1+10) + push encoding (1+5)
    try std.testing.expect(script.len > 0);
    try std.testing.expectEqual(@as(u8, @intFromEnum(Opcode.OP_RETURN)), script[0]);
}

test "encode/decode round-trip text/plain" {
    const allocator = std.testing.allocator;
    const original = BData{
        .content = "Hello World",
        .content_type = "text/plain",
        .encoding = "utf-8",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, original.content, decoded.content);
    try std.testing.expectEqualSlices(u8, original.content_type, decoded.content_type);
    try std.testing.expectEqualSlices(u8, original.encoding, decoded.encoding);
    try std.testing.expect(decoded.filename == null);
}

test "encode/decode round-trip with filename" {
    const allocator = std.testing.allocator;
    const original = BData{
        .content = "# Hello Markdown",
        .content_type = "text/markdown",
        .encoding = "utf-8",
        .filename = "readme.md",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, original.content, decoded.content);
    try std.testing.expectEqualSlices(u8, original.content_type, decoded.content_type);
    try std.testing.expectEqualSlices(u8, original.encoding, decoded.encoding);
    try std.testing.expectEqualSlices(u8, "readme.md", decoded.filename.?);
}

test "encode/decode round-trip binary content" {
    const allocator = std.testing.allocator;
    // PNG header bytes
    const png_header = [_]u8{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    const original = BData{
        .content = &png_header,
        .content_type = "image/png",
        .encoding = "binary",
        .filename = "test.png",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &png_header, decoded.content);
    try std.testing.expectEqualSlices(u8, "image/png", decoded.content_type);
    try std.testing.expectEqualSlices(u8, "binary", decoded.encoding);
    try std.testing.expectEqualSlices(u8, "test.png", decoded.filename.?);
}

test "encode/decode round-trip application/json" {
    const allocator = std.testing.allocator;
    const json = "{\"name\":\"test\",\"value\":42}";
    const original = BData{
        .content = json,
        .content_type = "application/json",
        .encoding = "utf-8",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, json, decoded.content);
    try std.testing.expectEqualSlices(u8, "application/json", decoded.content_type);
    try std.testing.expectEqualSlices(u8, "utf-8", decoded.encoding);
}

test "large content (> 520 bytes) splits into multiple pushes and reassembles" {
    const allocator = std.testing.allocator;

    // Create content larger than MAX_PUSH_SIZE
    var large_content: [1200]u8 = undefined;
    for (&large_content, 0..) |*byte, idx| {
        byte.* = @truncate(idx);
    }

    const original = BData{
        .content = &large_content,
        .content_type = "application/octet-stream",
        .encoding = "binary",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;
    // Content was split so decode allocated a merged buffer — must free it
    defer if (decoded.content.len > MAX_PUSH_SIZE) allocator.free(@constCast(decoded.content));

    try std.testing.expectEqual(@as(usize, 1200), decoded.content.len);
    try std.testing.expectEqualSlices(u8, &large_content, decoded.content);
    try std.testing.expectEqualSlices(u8, "application/octet-stream", decoded.content_type);
    try std.testing.expectEqualSlices(u8, "binary", decoded.encoding);
}

test "decode returns null for empty script" {
    const allocator = std.testing.allocator;
    const result = try decode(allocator, &.{});
    try std.testing.expect(result == null);
}

test "decode returns null for non-B script" {
    const allocator = std.testing.allocator;
    // OP_RETURN followed by a random prefix (not B)
    const bad_script = [_]u8{
        @intFromEnum(Opcode.OP_RETURN),
        0x03, 'f', 'o', 'o', // push "foo"
    };
    const result = try decode(allocator, &bad_script);
    try std.testing.expect(result == null);
}

test "decode returns null for truncated script" {
    const allocator = std.testing.allocator;
    // Just OP_RETURN and B prefix, no content
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    try appendOpcodes(&buf, allocator, &.{@intFromEnum(Opcode.OP_RETURN)});
    try appendPushData(&buf, allocator, B_PREFIX);

    const result = try decode(allocator, buf.items);
    try std.testing.expect(result == null);
}

test "encode/decode with empty content" {
    const allocator = std.testing.allocator;
    const original = BData{
        .content = "",
        .content_type = "text/plain",
        .encoding = "utf-8",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(usize, 0), decoded.content.len);
    try std.testing.expectEqualSlices(u8, "text/plain", decoded.content_type);
    try std.testing.expectEqualSlices(u8, "utf-8", decoded.encoding);
}

test "MediaType and Encoding enum conversions" {
    try std.testing.expectEqualSlices(u8, "text/plain", MediaType.text_plain.toBytes());
    try std.testing.expectEqualSlices(u8, "image/png", MediaType.image_png.toBytes());
    try std.testing.expectEqualSlices(u8, "application/octet-stream", MediaType.application_octet_stream.toBytes());
    try std.testing.expectEqualSlices(u8, "utf-8", Encoding.utf8.toBytes());
    try std.testing.expectEqualSlices(u8, "binary", Encoding.binary.toBytes());
}

test "encode using enum helpers" {
    const allocator = std.testing.allocator;
    const original = BData{
        .content = "<h1>hello</h1>",
        .content_type = MediaType.text_html.toBytes(),
        .encoding = Encoding.utf8.toBytes(),
        .filename = "index.html",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, "<h1>hello</h1>", decoded.content);
    try std.testing.expectEqualSlices(u8, "text/html", decoded.content_type);
    try std.testing.expectEqualSlices(u8, "utf-8", decoded.encoding);
    try std.testing.expectEqualSlices(u8, "index.html", decoded.filename.?);
}

test "exactly 520 bytes content is not split" {
    const allocator = std.testing.allocator;

    var content: [520]u8 = undefined;
    for (&content, 0..) |*byte, idx| {
        byte.* = @truncate(idx);
    }

    const original = BData{
        .content = &content,
        .content_type = "application/octet-stream",
        .encoding = "binary",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;

    // 520 bytes fits in one push, so no allocation needed in decode
    try std.testing.expectEqual(@as(usize, 520), decoded.content.len);
    try std.testing.expectEqualSlices(u8, &content, decoded.content);
}

test "521 bytes content is split into two pushes" {
    const allocator = std.testing.allocator;

    var content: [521]u8 = undefined;
    for (&content, 0..) |*byte, idx| {
        byte.* = @truncate(idx);
    }

    const original = BData{
        .content = &content,
        .content_type = "application/octet-stream",
        .encoding = "binary",
    };

    const script = try encode(allocator, original);
    defer allocator.free(script);

    const decoded = (try decode(allocator, script)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(@constCast(decoded.content));

    try std.testing.expectEqual(@as(usize, 521), decoded.content.len);
    try std.testing.expectEqualSlices(u8, &content, decoded.content);
}
