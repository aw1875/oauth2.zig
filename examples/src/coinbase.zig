const std = @import("std");

const httpz = @import("httpz");
const oauth2 = @import("oauth2");

const CoinbaseProvider = oauth2.CoinbaseProvider;

const SessionData = struct {
    state: []const u8,
    code_verifier: []const u8,
    expires_at: u64,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer if (gpa.deinit() != .ok) @panic("Failed to deinitialize allocator");

    var oauth2_provider = try CoinbaseProvider.init(allocator, .{
        .client_id = "<your_client_id>",
        .client_secret = "<your_client_secret>",
        .redirect_uri = "http://localhost:3000/api/v1/oauth/cb/callback", // Coinbase doesn't allow "coinbase" in the redirect callback path
    });
    defer oauth2_provider.deinit();

    var session_store = std.StringHashMap(SessionData).init(allocator);
    defer session_store.deinit();

    var app = App{ .coinbase = &oauth2_provider, .session_store = &session_store };

    var server = try httpz.Server(*App).init(allocator, .{ .port = 3000 }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    var router = try server.router(.{});
    router.get("/api/v1/oauth/cb", handleLogin, .{});
    router.get("/api/v1/oauth/cb/callback", handleCallback, .{}); // Coinbase doesn't allow "coinbase" in the redirect callback path

    std.log.info("Running Coinbase example project on port 3000", .{});
    try server.listen();
}

const App = struct {
    coinbase: *CoinbaseProvider,
    session_store: *std.StringHashMap(SessionData),
};

fn handleLogin(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const state = try oauth2.createStateNonce(res.arena);
    const code_verifier = try oauth2.createStateNonce(res.arena);
    const url = try app.coinbase.createAuthorizationUrl(res.arena, state, code_verifier, &[_][]const u8{ "wallet:user:read", "wallet:user:email" });

    const session_id = try oauth2.createStateNonce(res.arena);
    try app.session_store.put(session_id, SessionData{
        .state = state,
        .code_verifier = code_verifier,
        .expires_at = @intCast(std.time.milliTimestamp() + (60 * 5 * 1000)), // 5 minutes
    });

    try res.setCookie("example.sid", session_id, .{ .path = "/", .secure = true, .http_only = true, .max_age = 60 * 5 }); // Session ID cookie

    res.headers.add("Location", url);
    res.setStatus(.found);
}

fn handleCallback(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const query = try req.query();

    if (query.get("error") != null) {
        std.log.err("OAuth Error: {s}", .{query.get("error").?});
        return res.setStatus(.internal_server_error);
    }

    const code = query.get("code") orelse {
        std.log.err("Missing 'code' parameter in OAuth callback.", .{});
        return res.setStatus(.internal_server_error);
    };

    const state = query.get("state") orelse {
        std.log.err("Missing 'state' parameter in OAuth callback.", .{});
        return res.setStatus(.internal_server_error);
    };

    const session_id = req.cookies().get("example.sid") orelse {
        std.log.err("Missing 'session ID' cookie in OAuth callback.", .{});
        return res.setStatus(.bad_request);
    };

    try res.setCookie("example.sid", "", .{ .path = "/", .secure = true, .http_only = true, .max_age = 0 }); // Clear session ID cookie

    const session_data = app.session_store.fetchRemove(session_id) orelse {
        std.log.err("Invalid session ID: {s}", .{session_id});
        return res.setStatus(.bad_request);
    };

    if (std.time.milliTimestamp() > session_data.value.expires_at) {
        std.log.err("Session expired for ID: {s}", .{session_id});
        return res.setStatus(.unauthorized);
    }

    if (!std.mem.eql(u8, state, session_data.value.state)) {
        std.log.err("State mismatch: expected {s}, got {s}", .{ session_data.value.state, state });
        return res.setStatus(.bad_request);
    }

    const tokens = try app.coinbase.validateAuthorizationCode(res.arena, code, session_data.value.code_verifier);

    const user_profile = try getUserProfile(res.arena, "https://api.coinbase.com/v2/user", tokens.access_token);
    defer user_profile.deinit();

    return res.json(user_profile.value, .{});
}

fn getUserProfile(allocator: std.mem.Allocator, url: []const u8, access_token: []const u8) !std.json.Parsed(std.json.Value) {
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var response_storage = std.ArrayList(u8).init(allocator);
    defer response_storage.deinit();

    const response = try http_client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .headers = .{
            .authorization = .{ .override = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}) },
        },
        .extra_headers = &[_]std.http.Header{
            .{ .name = "User-Agent", .value = "oauth2.zig" },
            .{ .name = "Accept", .value = "application/json" },
        },
        .response_storage = .{ .dynamic = &response_storage },
    });

    if (response.status != .ok) return error.HttpError;

    return try std.json.parseFromSlice(std.json.Value, allocator, response_storage.items, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}
