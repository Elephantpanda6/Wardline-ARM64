const std = @import("std");
const common = @import("common");
const w = common.win32;
const sandbox = common.sandbox;

fn checkHcsAvailable() u8 {
    const dll_w = std.unicode.wtf8ToWtf16LeStringLiteral("computecore.dll");
    if (w.LoadLibraryW(dll_w)) |h| {
        _ = w.FreeLibrary(h);
        return 1;
    }
    return 0;
}

fn checkArm64PacBti() u8 {
    if (w.IsProcessorFeaturePresent(w.PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) != w.FALSE) {
        return 1;
    }
    var pac_policy: u32 = 0;
    if (w.GetProcessMitigationPolicy(w.GetCurrentProcess(), w.ProcessUserPointerAuthPolicy, &pac_policy, @sizeOf(u32)) != w.FALSE) {
        if ((pac_policy & 0x1) != 0) return 1;
    }
    return 0;
}

pub fn evaluateArm64SpawnPolicy(
    pe_class: common.WlPeClass,
    allow_arm64ec: bool,
    allow_prism_x64: bool,
    req_acg: bool,
) struct { status: common.WlStatusCode, emulation: bool, apply_acg: bool, detail: []const u8 } {
    return switch (pe_class) {
        .arm64 => .{
            .status = .ok,
            .emulation = false,
            .apply_acg = req_acg,
            .detail = "native ARM64 PE verified",
        },
        .arm64ec => if (allow_arm64ec) .{
            .status = .ok,
            .emulation = false,
            .apply_acg = req_acg,
            .detail = "ARM64EC PE verified",
        } else .{
            .status = .pe_disallowed_arch,
            .emulation = false,
            .apply_acg = false,
            .detail = "ARM64EC (0xA641) blocked unless allow_arm64ec is set",
        },
        .amd64 => if (allow_prism_x64) .{
            .status = .ok,
            .emulation = true,
            .apply_acg = false,
            .detail = "AMD64 PE allowed under Prism emulation with ACG suppressed",
        } else .{
            .status = .prism_blocked,
            .emulation = true,
            .apply_acg = false,
            .detail = "x64 Prism emulation blocked by default on win-arm64",
        },
        else => .{
            .status = .pe_disallowed_arch,
            .emulation = false,
            .apply_acg = false,
            .detail = "unsupported PE architecture for win-arm64",
        },
    };
}

export fn wl_engine_abi_version() callconv(.c) u32 {
    return common.abi_version;
}

export fn wl_engine_arch() callconv(.c) u32 {
    return @intFromEnum(common.WlArch.arm64);
}

export fn wl_classify_pe(bytes_ptr: ?[*]const u8, bytes_len: usize) callconv(.c) u32 {
    const ptr = bytes_ptr orelse return @intFromEnum(common.WlPeClass.unknown);
    return @intFromEnum(common.classifyPeBytes(ptr[0..bytes_len]));
}

export fn wl_probe_capabilities(out_caps: ?*common.WlHostCapabilities) callconv(.c) u32 {
    const caps = out_caps orelse return @intFromEnum(common.WlStatusCode.invalid_arg);

    var sys_info = std.mem.zeroes(w.SYSTEM_INFO);
    w.GetNativeSystemInfo(&sys_info);

    var os_ver = std.mem.zeroes(w.OSVERSIONINFOW);
    os_ver.dwOSVersionInfoSize = @sizeOf(w.OSVERSIONINFOW);
    _ = w.RtlGetVersion(&os_ver);

    var proc_machine: w.WORD = 0;
    var native_machine: w.WORD = 0;
    _ = w.IsWow64Process2(w.GetCurrentProcess(), &proc_machine, &native_machine);

    caps.* = .{
        .arch = @intFromEnum(common.WlArch.arm64),
        .abi_version = common.abi_version,
        .is_wow64_emulated = if (proc_machine != 0) 1 else 0,
        .cet_shadow_stack_supported = 0,
        .pac_bti_available = checkArm64PacBti(),
        .hyperv_hcs_available = checkHcsAvailable(),
        .appcontainer_supported = if (os_ver.dwBuildNumber >= 9200 or os_ver.dwMajorVersion >= 10) 1 else 0,
        .job_object_iocp_supported = 1,
        .reserved = .{ 0, 0 },
        .os_build_number = os_ver.dwBuildNumber,
        .page_size = sys_info.dwPageSize,
    };
    return @intFromEnum(common.WlStatusCode.ok);
}

export fn wl_spawn_isolated(
    req_opt: ?*const common.WlSpawnRequest,
    io_opt: ?*common.WlIoBuffers,
    res_opt: ?*common.WlSpawnResult,
) callconv(.c) u32 {
    const req = req_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const io = io_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const res = res_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    const pe_class = sandbox.inspectExecutablePeOnDisk(exe_slice);
    const eval = evaluateArm64SpawnPolicy(
        pe_class,
        req.allow_arm64ec != 0,
        req.allow_prism_x64 != 0,
        req.enable_acg != 0,
    );
    if (eval.status != .ok) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.emulation_detected = if (eval.emulation) 1 else 0;
        common.writeDetail(io, res, eval.detail);
        res.status_code = @intFromEnum(eval.status);
        return res.status_code;
    }

    var word0: u64 =
        w.MITIGATION_DEP_ENABLE |
        w.MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON |
        w.MITIGATION_HEAP_TERMINATE_ALWAYS_ON |
        w.MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON |
        w.MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON |
        w.MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON |
        w.MITIGATION_FONT_DISABLE_ALWAYS_ON;

    if (eval.apply_acg) {
        word0 |= w.MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    }

    return sandbox.executeIsolatedChild(
        req,
        io,
        res,
        .{ word0, 0 },
        1,
        eval.emulation,
        eval.apply_acg,
    );
}

export fn wl_create_hardened_pipe(
    name_utf8: ?[*]const u8,
    name_len: usize,
    out_handle: ?*usize,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    const ptr = name_utf8 orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const h = out_handle orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.createHardenedPipeImpl(ptr[0..name_len], h, e);
}

export fn wl_set_owner_only_dacl_utf8(
    path_utf8: ?[*]const u8,
    path_len: usize,
    is_dir: u8,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    _ = is_dir;
    const ptr = path_utf8 orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.setOwnerOnlyDaclImpl(ptr[0..path_len], e);
}

export fn wl_harden_current_process_dacl(out_win32_err: ?*u32) callconv(.c) u32 {
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.hardenCurrentProcessDaclImpl(e);
}

test "win-arm64 enforces Prism default-deny and conditional ACG suppression" {
    const denied = evaluateArm64SpawnPolicy(.amd64, false, false, true);
    try std.testing.expectEqual(common.WlStatusCode.prism_blocked, denied.status);
    try std.testing.expect(denied.emulation);

    const allowed_prism = evaluateArm64SpawnPolicy(.amd64, false, true, true);
    try std.testing.expectEqual(common.WlStatusCode.ok, allowed_prism.status);
    try std.testing.expect(allowed_prism.emulation);
    try std.testing.expect(!allowed_prism.apply_acg);

    const native_arm = evaluateArm64SpawnPolicy(.arm64, false, false, true);
    try std.testing.expectEqual(common.WlStatusCode.ok, native_arm.status);
    try std.testing.expect(!native_arm.emulation);
    try std.testing.expect(native_arm.apply_acg);
}
