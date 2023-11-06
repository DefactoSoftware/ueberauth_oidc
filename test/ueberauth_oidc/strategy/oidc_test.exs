defmodule Ueberauth.Strategy.OIDCTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Ueberauth.Strategy.OIDC

  @default_options [
    module: FakeOpenIDConnect,
    discovery_document_uri: "https://oidc.example/.well-known/discovery.json",
    response_type: "code",
    scope: "openid",
    client_id: "oidc_client",
    client_secret: "secret_value"
  ]

  describe "OIDC Strategy" do
    setup do
      {:ok, conn: init_test_session(conn(:get, "/auth/oidc"), %{})}
    end

    test "Handles an OIDC request", %{conn: conn} do
      conn = Ueberauth.run_request(conn, :provider, {OIDC, @default_options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOpenIDConnect.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => "http://www.example.com/auth/provider/callback",
               "client_id" => "oidc_client",
               "scope" => "openid",
               "response_type" => "code",
               "state" => _
             } = query
    end

    test "handle overriding configuration with application config", %{conn: conn} do
      Application.put_env(
        :ueberauth,
        Ueberauth.Strategy.OIDC,
        override_provider: [
          scope: "openid override-scope"
        ]
      )

      conn = Ueberauth.run_request(conn, :override_provider, {OIDC, @default_options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid override-scope"
             } = query
    end

    test "Handles an error in an OIDC request", %{conn: conn} do
      options = Keyword.delete(@default_options, :discovery_document_uri)
      conn = Ueberauth.run_request(conn, :provider, {OIDC, options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "error",
               message: "Authorization URL could not be constructed"
             } = error
    end

    test "Handle callback from provider with a callback_path", %{conn: conn} do
      options = Keyword.put(@default_options, :callback_path, "/custom_callback")
      conn = Ueberauth.run_request(conn, :provider, {OIDC, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)
      assert query["redirect_uri"] == "http://www.example.com/custom_callback"
    end

    test "Handle callback from provider with custom request scopes", %{conn: conn} do
      options = Keyword.put(@default_options, :scope, "openid custom")
      conn = Ueberauth.run_request(conn, :provider, {OIDC, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid custom"
             } = query
    end

    test "handle additional request parameters", %{conn: conn} do
      options = Keyword.put(@default_options, :request_params, %{"request" => "param"})
      conn = Ueberauth.run_request(conn, :provider, {OIDC, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "request" => "param"
             } = query
    end

    test "handle overriden request_uri", %{conn: conn} do
      options =
        Keyword.put(@default_options, :request_uri, "https://oidc-override.example/request")

      conn = Ueberauth.run_request(conn, :provider, {OIDC, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "https://oidc-override.example/request?")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => _,
               "client_id" => _,
               "scope" => _,
               "state" => _,
               "response_type" => _
             } = query
    end

    test "Handle callback from OIDC with default uid field (sub)", %{conn: conn} do
      conn = run_request_and_callback(conn)

      assert %Ueberauth.Auth{
               provider: :provider,
               strategy: Ueberauth.Strategy.OIDC,
               uid: "sub_value",
               credentials: %Ueberauth.Auth.Credentials{
                 expires: true,
                 expires_at: 10_000_000_000,
                 token: "access_token_value",
                 token_type: "Bearer",
                 refresh_token: "refresh_token_value",
                 other: %{id_token: "id_token_value"}
               },
               info: %Ueberauth.Auth.Info{email: "email_value"},
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   opts: %{discovery_document_uri: _},
                   claims: %{"sub" => _},
                   userinfo: nil
                 }
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an overriden uid field", %{conn: conn} do
      options = Keyword.put(@default_options, :uid_field, "email")
      conn = run_request_and_callback(conn, options)

      assert %Ueberauth.Auth{
               uid: "email_value"
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an missing uid field", %{conn: conn} do
      options = Keyword.put(@default_options, :uid_field, "_missing_")
      conn = run_request_and_callback(conn, options)

      assert %Ueberauth.Auth{
               uid: nil
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a userinfo endpoint and an override userinfo_uid_field",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:fetch_userinfo, true)
        |> Keyword.put(:userinfo_uid_field, "email")

      conn = run_request_and_callback(conn, options)

      assert %Ueberauth.Auth{
               uid: "test@email.example",
               info: %Ueberauth.Auth.Info{
                 name: "Full Name",
                 first_name: "First",
                 last_name: "Last",
                 nickname: "Nickname",
                 email: "test@email.example",
                 image: "http://photo.example",
                 phone: "phone_number_value",
                 birthday: "1970-01-01",
                 urls: %{
                   profile: "http://profile.example",
                   website: "http://website.example"
                 }
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a missing code", %{conn: conn} do
      conn_with_cookies = Ueberauth.run_request(conn, :provider, {OIDC, @default_options})
      state_cookie = conn_with_cookies.resp_cookies["ueberauth.state_param"].value

      conn = %{
        conn
        | params: %{
            "state" => state_cookie
          },
          cookies: %{"ueberauth.state_param" => state_cookie}
      }

      conn = Ueberauth.run_callback(conn, :provider, {OIDC, @default_options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "error",
               message: "Query string does not contain field 'code'"
             } = error
    end

    test "Handle callback from provider with an error fetching tokens", %{conn: conn} do
      options = Keyword.put(@default_options, :_fetch_tokens, false)

      conn = run_request_and_callback(conn, options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "error",
               message: :no_tokens
             } = error
    end

    test "Handle callback from provider with an error verifying tokens", %{conn: conn} do
      options = Keyword.put(@default_options, :_verify_tokens, false)

      conn = run_request_and_callback(conn, options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "error",
               message: :invalid
             } = error
    end

    test "Handle callback from provider with an error fetching userinfo", %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:fetch_userinfo, true)
        |> Keyword.put(:_fetch_userinfo, false)

      conn = run_request_and_callback(conn, options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "error",
               message: :invalid
             } = error
    end

    test "handle cleanup of uberauth values in the conn" do
      conn_with_values = %Plug.Conn{
        private: %{
          ueberauth_oidc_opts: :some_value,
          ueberauth_oidc_claims: :other_value,
          uebrauth_oidc_tokens: :another_value,
          ueberauth_oidc_userinfo: :different_value
        }
      }

      assert %Plug.Conn{
               private: %{
                 ueberauth_oidc_opts: nil,
                 ueberauth_oidc_claims: nil,
                 ueberauth_oidc_tokens: nil,
                 ueberauth_oidc_userinfo: nil
               }
             } = OIDC.handle_cleanup!(conn_with_values)
    end

    test "Parses a binary exp value" do
      conn = %Plug.Conn{
        private: %{
          ueberauth_oidc_tokens: %{
            "id_token" => "4321",
            "access_token" => "1234",
            "token_type" => "Bearer"
          },
          ueberauth_oidc_claims: %{
            "exp" => "1234"
          },
          ueberauth_oidc_opts: [provider: "some_provider"]
        }
      }

      assert %Ueberauth.Auth.Credentials{
               expires: true,
               expires_at: 1234
             } = OIDC.credentials(conn)
    end
  end

  defp run_request_and_callback(conn, options \\ @default_options) do
    conn_with_cookies = Ueberauth.run_request(conn, :provider, {OIDC, options})
    state_cookie = conn_with_cookies.resp_cookies["ueberauth.state_param"].value

    conn = %{
      conn
      | params: %{
          "code" => FakeOpenIDConnect.callback_code(),
          "state" => state_cookie
        },
        cookies: %{"ueberauth.state_param" => state_cookie}
    }

    Ueberauth.run_callback(conn, :provider, {OIDC, options})
  end
end
