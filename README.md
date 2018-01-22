# Überauth OIDC

> Generic OpenID Connect strategy for Ueberauth.

This library provides an Ueberauth OIDC strategy implemented as a thin `:oidcc` client.
It is a leaky abstraction, and thus requires some knowledge of `:oidcc` to configure and use.

## Installation

1. Add `:ueberauth_oidc` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_oidc, git: "https://github.com/rng2/ueberauth_oidc.git", tag: "0.0.1"}]
    end
    ```

## Configuration

1. Add OIDC to your Ueberauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        oidc: { Ueberauth.Strategy.OIDC, [
          default: [
            # required
            provider: :auth0,

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
See [:oidcc docs](https://github.com/indigo-dc/oidcc#setup-an-openid-connect-provider)
for a list of supported options.

    ```elixir
    config :ueberauth, UeberauthOIDC,
      # required
      local_endpoint: "http://host:port/auth/oidc/callback",

      # one or more providers
      auth0: [
        # required
        issuer_or_config_endpoint: "https://myapp.auth0.com",
        client_id: "CLIENT_ID",
        client_secret: "CLIENT_SECRET",

        # other oidcc options (excluding :static_extend_url)
        request_scopes: ["openid", "profile", "email"]
        ...
      ],
      google: [
        ...
      ]
    ```

1. Configure `:oidcc`. See the [docs](https://github.com/indigo-dc/oidcc#configuration)
for a list of supported options.

    ```elixir
    config :oidcc,
      # required
      cacertfile: "path/to/cacert.pem",

      # optional
      cert_depth: 5,
      support_none_algorithm: false,
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

   - The `other` map in `Ueberauth.Auth.Credentials` contains `provider` and `id_token`

   - `Ueberauth.Strategy.Extra` contains the raw token map returned from `:oidcc`,
     including all claims extracted from the id token.

1.  Call `UeberauthOIDC.init!/0` during application startup:

	```elixir
    def start(_type, _args) do
      ...
      # initialize ueberauth_oidc
      UeberauthOIDC.init!()
      ...
    end
    ```

## Calling

Depending on the configured url, you can initialize the request through:

    /auth/oidc

To use another provider instead of the configured default, add the `oidc_provider` option:

    /auth/oidc?oidc_provider=google

## License

Please see [LICENSE](https://github.com/rng2/ueberauth_oidc/blob/master/LICENSE)
for licensing details.
