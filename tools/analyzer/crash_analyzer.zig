//! Crash Analyzer
//!
//! Reads a crash sample file and displays hex dump + ASCII representation.
//! Useful for quickly inspecting fuzzer crash outputs before loading into GDB.
//!
//! Usage: crash-analyzer <crash-file>

const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = std.fs.File.stdout().writer(&stdout_buf);
    var stderr_w = std.fs.File.stderr().writer(@constCast(&.{}));
    const stdout = &stdout_w.interface;
    const stderr = &stderr_w.interface;
    defer stdout.flush() catch {};

    if (args.len < 2) {
        try stderr.print("Usage: {s} <crash-file>\n", .{args[0]});
        std.process.exit(1);
    }

    const file_path = args[1];

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        try stderr.print("Error opening '{s}': {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer file.close();

    const data = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        try stderr.print("Error reading file: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(data);

    try stdout.print("=== Crash Sample Analysis ===\n", .{});
    try stdout.print("File: {s}\n", .{file_path});
    try stdout.print("Size: {} bytes\n\n", .{data.len});

    // Hex dump
    try hexDump(stdout, data);

    // Summary
    try stdout.print("\n=== Summary ===\n", .{});
    try stdout.print("Printable bytes: {}\n", .{countPrintable(data)});
    try stdout.print("Null bytes:      {}\n", .{countByte(data, 0x00)});
    try stdout.print("0x41 ('A'):      {}\n", .{countByte(data, 0x41)});
    try stdout.print("0x90 (NOP):      {}\n", .{countByte(data, 0x90)});
}

fn hexDump(writer: anytype, data: []const u8) !void {
    const bytes_per_line = 16;
    var offset: usize = 0;

    while (offset < data.len) {
        // Offset
        try writer.print("{x:0>8}  ", .{offset});

        // Hex bytes
        const line_end = @min(offset + bytes_per_line, data.len);
        for (offset..line_end) |i| {
            try writer.print("{x:0>2} ", .{data[i]});
            if (i - offset == 7) try writer.print(" ", .{});
        }

        // Padding if short line
        if (line_end - offset < bytes_per_line) {
            const missing = bytes_per_line - (line_end - offset);
            for (0..missing) |_| try writer.print("   ", .{});
            if (line_end - offset <= 8) try writer.print(" ", .{});
        }

        // ASCII
        try writer.print(" |", .{});
        for (offset..line_end) |i| {
            const c = data[i];
            if (c >= 0x20 and c <= 0x7e) {
                try writer.print("{c}", .{c});
            } else {
                try writer.print(".", .{});
            }
        }
        try writer.print("|\n", .{});

        offset = line_end;
    }
}

fn countPrintable(data: []const u8) usize {
    var count: usize = 0;
    for (data) |b| {
        if (b >= 0x20 and b <= 0x7e) count += 1;
    }
    return count;
}

fn countByte(data: []const u8, target: u8) usize {
    var count: usize = 0;
    for (data) |b| {
        if (b == target) count += 1;
    }
    return count;
}
