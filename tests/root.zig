const std = @import("std");
const templates = @import("zig-templates");

test {
    std.testing.refAllDeclsRecursive(templates);
}
