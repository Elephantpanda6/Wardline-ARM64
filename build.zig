const std = @import("std");
const builtin = @import("builtin");

const EngineSpec = struct {
    step_name: []const u8,
    subdir: []const u8,
    lib_name: []const u8,
    source: []const u8,
    query: std.Target.Query,
};

fn makeEngineLib(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    spec: EngineSpec,
) struct { lib: *std.Build.Step.Compile, mod: *std.Build.Module } {
    const target = b.resolveTargetQuery(spec.query);

    const common_mod = b.createModule(.{
        .root_source_file = b.path("platforms/common/common.zig"),
        .target = target,
        .optimize = optimize,
    });
    common_mod.link_libc = true;
    common_mod.addIncludePath(b.path("platforms/common"));

    const engine_mod = b.createModule(.{
        .root_source_file = b.path(spec.source),
        .target = target,
        .optimize = optimize,
    });
    engine_mod.link_libc = true;
    engine_mod.addImport("common", common_mod);
    engine_mod.addIncludePath(b.path("platforms/common"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = spec.lib_name,
        .root_module = engine_mod,
    });
    return .{ .lib = lib, .mod = engine_mod };
}

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const specs = [_]EngineSpec{
        .{
            .step_name = "win-arm64",
            .subdir = "win-arm64",
            .lib_name = "wardline_engine_arm64",
            .source = "platforms/win-arm64/engine_arm64.zig",
            .query = .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .gnu },
        },
        .{
            .step_name = "linux-arm64",
            .subdir = "linux-arm64",
            .lib_name = "wardline_engine_arm64",
            .source = "platforms/linux/engine_linux.zig",
            .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
        },
        .{
            .step_name = "macos-arm64",
            .subdir = "macos-arm64",
            .lib_name = "wardline_engine_arm64",
            .source = "platforms/macos/engine_macos.zig",
            .query = .{ .cpu_arch = .aarch64, .os_tag = .macos },
        },
        .{
            .step_name = "freebsd-arm64",
            .subdir = "freebsd-arm64",
            .lib_name = "wardline_engine_arm64",
            .source = "platforms/bsd/engine_bsd.zig",
            .query = .{ .cpu_arch = .aarch64, .os_tag = .freebsd },
        },
    };

    const all_step = b.step("all-engines", "Build static ARM64 engines for Windows, Linux, macOS, and FreeBSD");

    const default_os_tag = builtin.os.tag;
    var default_installed = false;

    for (specs) |spec| {
        const built = makeEngineLib(b, optimize, spec);
        const step = b.step(spec.step_name, b.fmt("Build static engine for {s}", .{spec.step_name}));
        const inst_default = b.addInstallArtifact(built.lib, .{});
        step.dependOn(&inst_default.step);

        const inst_sub = b.addInstallArtifact(built.lib, .{
            .dest_dir = .{ .override = .{ .custom = spec.subdir } },
        });
        all_step.dependOn(&inst_sub.step);

        if (spec.query.os_tag == default_os_tag) {
            b.installArtifact(built.lib);
            default_installed = true;
        }
    }

    if (!default_installed) {
        const win_built = makeEngineLib(b, optimize, specs[0]);
        b.installArtifact(win_built.lib);
    }

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

    const common_tests_step = b.step("common-tests", "Run shared cross-OS binary classifier and ABI tests");
    common_tests_step.dependOn(&b.addRunArtifact(test_common_host).step);

    const win_built = makeEngineLib(b, optimize, specs[0]);
    const test_arm64_win = b.addTest(.{
        .name = "win-arm64-tests",
        .root_module = win_built.mod,
    });

    const test_step = b.step(
        "test",
        "Run shared & host Zig tests natively and compile cross-OS ARM64 engine tests",
    );

    if (builtin.cpu.arch == .aarch64 and builtin.os.tag == .windows) {
        test_step.dependOn(&b.addRunArtifact(test_common_host).step);
        test_step.dependOn(&b.addRunArtifact(test_arm64_win).step);
    } else {
        test_step.dependOn(&b.addRunArtifact(test_common_host).step);
        test_step.dependOn(&b.addInstallArtifact(test_arm64_win, .{}).step);
    }
}
