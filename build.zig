const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const arm64_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .windows,
        .abi = .gnu,
    });

    const common_arm64 = b.createModule(.{
        .root_source_file = b.path("platforms/common/common.zig"),
        .target = arm64_target,
        .optimize = optimize,
    });
    common_arm64.link_libc = true;
    common_arm64.addIncludePath(b.path("platforms/common"));

    const engine_arm64_mod = b.createModule(.{
        .root_source_file = b.path("platforms/win-arm64/engine_arm64.zig"),
        .target = arm64_target,
        .optimize = optimize,
    });
    engine_arm64_mod.link_libc = true;
    engine_arm64_mod.addImport("common", common_arm64);
    engine_arm64_mod.addIncludePath(b.path("platforms/common"));

    const lib_arm64 = b.addLibrary(.{
        .linkage = .static,
        .name = "wardline_engine_arm64",
        .root_module = engine_arm64_mod,
    });
    b.installArtifact(lib_arm64);

    const test_common = b.addTest(.{
        .name = "common-arm64-tests",
        .root_module = common_arm64,
    });
    const test_arm64 = b.addTest(.{
        .name = "win-arm64-tests",
        .root_module = engine_arm64_mod,
    });

    const test_step = b.step(
        "test",
        "Run shared & ARM64 Zig unit tests natively on ARM64, or compile ARM64 tests on x64 hosts",
    );

    if (builtin.cpu.arch == .aarch64 and builtin.os.tag == .windows) {
        test_step.dependOn(&b.addRunArtifact(test_common).step);
        test_step.dependOn(&b.addRunArtifact(test_arm64).step);
    } else {
        const common_host = b.createModule(.{
            .root_source_file = b.path("platforms/common/common.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        });
        common_host.link_libc = true;
        common_host.addIncludePath(b.path("platforms/common"));
        const test_common_host = b.addTest(.{
            .name = "common-host-tests",
            .root_module = common_host,
        });
        test_step.dependOn(&b.addRunArtifact(test_common_host).step);
        test_step.dependOn(&b.addInstallArtifact(test_arm64, .{}).step);
    }
}
