# oauth2.zig Examples

These are some examples on how to use different providers. To run an example, add your `client_id` and `client_secret` to the example code where you see `<your_client_id>` and `<your_client_secret>`, then run the example with:
```sh
zig build run-<example_name> # For example, `zig build run-google`
```

Each example will guide you through the OAuth2 flow for the respective provider and pull the user's profile information to show an example use case. Some notes, the examples are storing session data (such as state and code_verifier) in memory, but in a production environment you'd most likely want to use a database, redis, or some other persistent storage mechanism. These examples are meant to be simple and illustrative.
