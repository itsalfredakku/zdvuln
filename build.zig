const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    // --- Build options for mitigation control ---
    const no_canary = b.option(bool, "no-canary", "Disable stack canary (-fno-stack-protector)") orelse true;
    const no_pie = b.option(bool, "no-pie", "Disable position-independent executable") orelse true;

    // --- C compilation flags ---
    var flag_buf: [4][]const u8 = undefined;
    var flag_count: usize = 0;

    // Always include debug info for GDB analysis
    flag_buf[flag_count] = "-g";
    flag_count += 1;
    flag_buf[flag_count] = "-O0";
    flag_count += 1;

    if (no_canary) {
        flag_buf[flag_count] = "-fno-stack-protector";
        flag_count += 1;
    }
    if (no_pie) {
        flag_buf[flag_count] = "-fno-pie";
        flag_count += 1;
    }

    const flags = flag_buf[0..flag_count];

    // ========================================
    // Stack targets
    // ========================================
    _ = addCTarget(b, target, "stack-basic", &.{"targets/stack/stack_basic.c"}, flags);
    _ = addCTarget(b, target, "stack-redirect", &.{"targets/stack/stack_redirect.c"}, flags);
    _ = addCTarget(b, target, "off-by-one", &.{"targets/stack/off_by_one.c"}, flags);

    // ========================================
    // Heap targets
    // ========================================
    _ = addCTarget(b, target, "heap-overflow", &.{"targets/heap/heap_overflow.c"}, flags);
    _ = addCTarget(b, target, "use-after-free", &.{"targets/heap/use_after_free.c"}, flags);
    _ = addCTarget(b, target, "double-free", &.{"targets/heap/double_free.c"}, flags);

    // ========================================
    // Logic targets
    // ========================================
    _ = addCTarget(b, target, "format-string", &.{"targets/logic/format_string.c"}, flags);
    _ = addCTarget(b, target, "integer-overflow", &.{"targets/logic/integer_overflow.c"}, flags);
    _ = addCTarget(b, target, "type-confusion", &.{"targets/logic/type_confusion.c"}, flags);
    _ = addCTarget(b, target, "signedness-bug", &.{"targets/logic/signedness_bug.c"}, flags);
    _ = addCTarget(b, target, "uninitialized", &.{"targets/logic/uninitialized.c"}, flags);

    // ========================================
    // Parser targets
    // ========================================
    _ = addCTarget(b, target, "parser-server", &.{"targets/parser/parser_server.c"}, flags);
    _ = addCTarget(b, target, "image-parser", &.{"targets/parser/image_parser.c"}, flags);

    // ========================================
    // Concurrency targets
    // ========================================
    _ = addCTarget(b, target, "race-condition", &.{"targets/concurrency/race_condition.c"}, flags);

    // ========================================
    // Zig tools
    // ========================================
    const crash_analyzer = b.addExecutable(.{
        .name = "crash-analyzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/analyzer/crash_analyzer.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    b.installArtifact(crash_analyzer);

    const packet_sender = b.addExecutable(.{
        .name = "packet-sender",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/harness/packet_sender.zig"),
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        }),
    });
    b.installArtifact(packet_sender);

    // ========================================
    // Exploit development tools
    // ========================================
    const pattern_gen = b.addExecutable(.{
        .name = "pattern-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/exploit/pattern_gen.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    b.installArtifact(pattern_gen);

    const rop_scanner = b.addExecutable(.{
        .name = "rop-scanner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/exploit/rop_scanner.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    b.installArtifact(rop_scanner);

    const zdf_craft = b.addExecutable(.{
        .name = "zdf-craft",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/exploit/zdf_craft.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    b.installArtifact(zdf_craft);
}

fn addCTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    name: []const u8,
    sources: []const []const u8,
    flags: []const []const u8,
) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = .Debug,
        .link_libc = true,
    });

    for (sources) |src| {
        mod.addCSourceFile(.{
            .file = b.path(src),
            .flags = flags,
        });
    }

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = mod,
    });
    b.installArtifact(exe);
    return exe;
}
