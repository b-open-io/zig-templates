pub const inscription = @import("inscription.zig");
pub const bitcom = @import("bitcom/lib.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
