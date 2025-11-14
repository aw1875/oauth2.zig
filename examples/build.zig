const std = @import("std");

const example_projects = [_]struct { name: []const u8, path: []const u8 }{
    .{ .name = "multiple-providers", .path = "src/multiple-providers.zig" },
    .{ .name = "google", .path = "src/google.zig" },
    .{ .name = "linkedin", .path = "src/linkedin.zig" },
    .{ .name = "github", .path = "src/github.zig" },
    .{ .name = "discord", .path = "src/discord.zig" },
    .{ .name = "coinbase", .path = "src/coinbase.zig" },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    for (example_projects) |p| {
        const exe = b.addExecutable(.{
            .name = p.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(p.path),
                .target = target,
                .optimize = optimize,
            }),
        });

        const httpz = b.dependency("httpz", .{ .target = target, .optimize = optimize });
        exe.root_module.addImport("httpz", httpz.module("httpz"));

        const oauth2 = b.dependency("oauth2", .{ .target = target, .optimize = optimize });
        exe.root_module.addImport("oauth2", oauth2.module("oauth2"));

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step_name = std.fmt.allocPrint(b.allocator, "run-{s}", .{p.name}) catch "run";
        const run_step = b.step(run_step_name, std.fmt.allocPrint(b.allocator, "Run the {s} app", .{p.name}) catch "Run app");
        run_step.dependOn(&run_cmd.step);
    }
}
