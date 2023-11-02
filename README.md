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
      [{:ueberauth_oidc, github: "mbta/ueberauth_oidc"}]
    end
    ```

   Or if available in hex:

   ```elixir
    def deps do
      [{:ueberauth_oidc, "~> 1.0"}]
    end
   ```

## Configuration

1. Add OIDC to your Ueberauth configuration.
See [OpenIDConnect](https://github.com/DockYard/openid_connect/blob/master/README.md) and [Ueberauth](https://hexdocs.pm/ueberauth/readme.html#configuring-providers)
for a list of supported options.

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        oidc: { Ueberauth.Strategy.OIDC,
          discovery_document_uri: "https://oidc.example/.well-known/openid-configuration",
          client_id: "client_id",
          client_secret: "123456789",
          response_type: "code",
          scope: "openid profile email",
          # optional
          callback_path: "/auth/oidc/callback",
          fetch_userinfo: true, # true/false
          userinfo_uid_field: "upn", # only include if getting the user_id from userinfo
          uid_field: "sub" # only include if getting the user_id from the claims,
          request_params: %{} # additional parameters for the initial request
          request_uri: "https://oidc-override/request" # override the initial request URI
        }
      ]
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

   - `Ueberauth.Auth.Credentials` contains the `access_token` and related fields

   - The `other` map in `Ueberauth.Auth.Credentials` contains `id_token`

   - `Ueberauth.Strategy.Extra` contains the raw claims, userinfo, and tokens 

## Calling

Depending on the configured url, you can initialize the request through:

    /auth/oidc

## License

Please see [LICENSE](https://github.com/DefactoSoftware/ueberauth_oidc/blob/master/LICENSE)
for licensing details.

Based on:
- [rng2/ueberauth_oidc](https://github.com/rng2/ueberauth_oidc)
