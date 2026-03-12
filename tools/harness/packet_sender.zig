//! Packet Sender
//!
//! Sends crafted protocol packets to the vulnerable parser server.
//! Useful for manually testing parser bugs before setting up a fuzzer.
//!
//! Usage: packet-sender <host> <port> <type> <data>
//! Example: packet-sender 127.0.0.1 9999 1 "AAAAAAAAAA"
//!
//! Protocol: [TYPE:1][LENGTH:2 little-endian][DATA:LENGTH]

const std = @import("std");
const net = std.net;
const posix = std.posix;

const PacketHeader = packed struct {
    pkt_type: u8,
    length: u16,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5) {
        var stderr_w = std.fs.File.stderr().writer(@constCast(&.{}));
        const stderr = &stderr_w.interface;
        try stderr.print("Usage: {s} <host> <port> <type> <data>\n", .{args[0]});
        try stderr.print("  type: 1=ECHO, 2=AUTH, 3=DATA\n", .{});
        try stderr.print("  data: string payload (use quotes for spaces)\n", .{});
        try stderr.print("\nExample: {s} 127.0.0.1 9999 1 \"AAAA\"\n", .{args[0]});
        std.process.exit(1);
    }

    const host = args[1];
    const port = std.fmt.parseInt(u16, args[2], 10) catch {
        std.debug.print("Invalid port: {s}\n", .{args[2]});
        std.process.exit(1);
    };
    const pkt_type = std.fmt.parseInt(u8, args[3], 10) catch {
        std.debug.print("Invalid type: {s}\n", .{args[3]});
        std.process.exit(1);
    };
    const data = args[4];

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_w.interface;
    defer stdout.flush() catch {};
    try stdout.print("=== Packet Sender ===\n", .{});
    try stdout.print("Target:  {s}:{}\n", .{ host, port });
    try stdout.print("Type:    0x{x:0>2}\n", .{pkt_type});
    try stdout.print("Data:    {s} ({} bytes)\n", .{ data, data.len });

    // Build packet
    const header = PacketHeader{
        .pkt_type = pkt_type,
        .length = @intCast(data.len),
    };

    var packet: std.ArrayList(u8) = .{};
    defer packet.deinit(allocator);

    try packet.appendSlice(allocator, std.mem.asBytes(&header));
    try packet.appendSlice(allocator, data);

    try stdout.print("Packet:  {} bytes total\n\n", .{packet.items.len});

    // Connect and send
    const address = net.Address.parseIp4(host, port) catch {
        std.debug.print("Invalid address: {s}:{}\n", .{ host, port });
        std.process.exit(1);
    };

    const stream = net.tcpConnectToAddress(address) catch |err| {
        std.debug.print("Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer stream.close();

    _ = stream.write(packet.items) catch |err| {
        std.debug.print("Send failed: {}\n", .{err});
        std.process.exit(1);
    };

    try stdout.print("[*] Packet sent.\n", .{});
}
