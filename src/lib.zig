pub const inscription = @import("inscription.zig");
pub const bitcom = @import("bitcom/lib.zig");
pub const lock = @import("lock.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
