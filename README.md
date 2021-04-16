# Überauth OIDC

> OIDC Provider for Ueberauth using the OpenIDProvider library.

This library provides an OIDC strategy for Ueberauth using the information in the `/.well-known` url.
Only supports `authorization_code` flow for now.
Has optional support for `/userinfo` endpoints, and has the option to get a user's `uid_field` from either the claims or the userinfo.

*Originally based on rng2/ueberauth_oidc but has now diverged significantly from the source*

## Installation

1. Add `:ueberauth_oidc` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_oidc, git: "https://github.com/DefactoSoftware/ueberauth_oidc.git"}]
    end
    ```

   Or if available in hex:

   ```elixir
    def deps do
      [{:ueberauth_oidc, "~> 1.0"}]
    end
   ```

## Configuration

1. Add OIDC to your Ueberauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        oidc: { Ueberauth.Strategy.OIDC, [
          default: [
            # required, set to default provider you want to use
            provider: :default_oidc,

            # optional
            uid_field: :sub
          ],

          # optional override for each provider
          google: [uid_field: :email],
          ...
        ] }
      ]
    ```

1. Update your provider configuration.
See [OpenIDConnect](https://hexdocs.pm/openid_connect/readme.html)
for a list of supported options.

    ```elixir
    config :ueberauth, Ueberauth.Strategy.OIDC,
      # one or more providers
      default_oidc: [
        fetch_userinfo: true, # true/false
        userinfo_uid_field: "upn", # only include if getting the user_id from userinfo
        uid_field: "sub" # only include if getting the user_id from the claims
        discovery_document_uri: "https://oidc.example/.well-known/openid-configuration",
        client_id: "client_id",
        client_secret: "123456789",
        redirect_uri: "https://your.url/auth/oidc/callback",
        response_type: "code",
        scope: "openid profile email"
      ],
      ...
    ```

## Usage

1. Include the Ueberauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller
      plug Ueberauth
      ...
    end
    ```

1. Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:unused", AuthController, :request
      get "/:unused/callback", AuthController, :callback
    end
    ```

1. Your controller needs to implement callbacks to deal with `Ueberauth.Auth`
and `Ueberauth.Failure` responses. For an example implementation see the
[Ueberauth Example](https://github.com/ueberauth/ueberauth_example) application.
Note that the `Ueberauth.Strategy.Info` struct stored in `Ueberauth.Auth`
will be empty. Use the information in `Ueberauth.Auth.Credentials` and
`Ueberauth.Strategy.Extra` instead:

   - `Ueberauth.Auth.Credentials` contains the `access_token` and related fields

   - The `other` map in `Ueberauth.Auth.Credentials` contains `provider` and `user_info`

   - `Ueberauth.Strategy.Extra` contains the raw claims, tokens and opts

1.  Add `OpenIDConnect.Worker` with a provider list during application startup:

	  ```elixir
    def start(_type, _args) do
      ...
      children = [
        ...,
        {OpenIDConnect.Worker, Application.get_env(:ueberauth, Ueberauth.Strategy.OIDC)},
        ...
      ]
      ...
      Supervisor.start_link(children, opts)
    end
    ```

## Calling

Depending on the configured url, you can initialize the request through:

    /auth/oidc

To use another provider instead of the configured default, add the `oidc_provider` option:

    /auth/oidc?oidc_provider=google

## License

Please see [LICENSE](https://github.com/DefactoSoftware/ueberauth_oidc/blob/master/LICENSE)
for licensing details.

Loosely based on [rng2/ueberauth_oidc](https://github.com/rng2/ueberauth_oidc).
