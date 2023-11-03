defmodule Ueberauth.Strategy.OIDC do
  @moduledoc """
  OIDC Strategy for Ueberauth.
  """

  use Ueberauth.Strategy

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  @doc """
  Handles the initial authentication request.
  """
  def handle_request!(conn) do
    opts = get_options!(conn)
    params = params_from_conn(conn)

    params =
      if request_params = Map.get(opts, :request_params) do
        Map.merge(params, request_params)
      else
        params
      end

    try do
      {:ok, uri} =
        if request_uri = Map.get(opts, :request_uri) do
          params =
            Map.merge(
              params,
              %{
                "client_id" => opts.client_id,
                "redirect_uri" => opts.redirect_uri,
                "response_type" => opts.response_type,
                "scope" => opts.scope
              }
            )

          query = URI.encode_query(params)
          {:ok, "#{request_uri}?#{query}"}
        else
          opts.module.authorization_uri(opts, params)
        end

      redirect!(conn, uri)
    rescue
      _ ->
        set_error!(
          conn,
          "error",
          "Authorization URL could not be constructed"
        )
    end
  end

  @doc """
  Handles the callback from the oidc provider.
  """
  def handle_callback!(conn) do
    case conn.params["code"] do
      nil ->
        set_error!(conn, "error", "Query string does not contain field 'code'")

      code ->
        opts = get_options!(conn)
        params = params_from_conn(conn, %{code: code})

        with {:ok, %{"access_token" => access_token, "id_token" => id_token} = tokens} <-
               opts.module.fetch_tokens(opts, params),
             {:ok, claims} <- opts.module.verify(opts, id_token) do
          conn
          |> put_private(:ueberauth_oidc_claims, claims)
          |> put_private(:ueberauth_oidc_tokens, tokens)
          |> put_private(:ueberauth_oidc_opts, opts)
          |> maybe_put_userinfo(opts, access_token)
        else
          {:error, reason} ->
            set_error!(conn, "error", reason)
        end
    end
  end

  defp params_from_conn(conn, params \\ %{}) do
    []
    |> with_state_param(conn)
    |> Map.new()
    |> Map.merge(params)
  end

  defp maybe_put_userinfo(conn, opts, access_token) do
    with true <- Map.get(opts, :fetch_userinfo, false),
         {:ok, userinfo} <- opts.module.fetch_userinfo(opts, access_token) do
      put_private(conn, :ueberauth_oidc_userinfo, userinfo)
    else
      false ->
        conn

      {:error, reason} ->
        set_error!(conn, "error", reason)
    end
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ueberauth_oidc_opts, nil)
    |> put_private(:ueberauth_oidc_claims, nil)
    |> put_private(:ueberauth_oidc_tokens, nil)
    |> put_private(:ueberauth_oidc_userinfo, nil)
  end

  @doc """
  Returns the configured uid field from the id token.
  """
  def uid(conn) do
    private = conn.private

    with true <- Map.get(private.ueberauth_oidc_opts, :fetch_userinfo, false),
         userinfo when is_bitstring(userinfo) <-
           Map.get(private.ueberauth_oidc_opts, :userinfo_uid_field, "sub") do
      private.ueberauth_oidc_userinfo[userinfo]
    else
      _ ->
        uid_field = Map.get(private.ueberauth_oidc_opts, :uid_field, "sub")
        private.ueberauth_oidc_claims[uid_field]
    end
  end

  @doc """
  Returns the credentials from the oidc response.

  `other` includes `provider` and `id_token`
  """
  def credentials(conn) do
    private = conn.private
    claims = private.ueberauth_oidc_claims
    tokens = private.ueberauth_oidc_tokens

    exp_at = expires_at(claims["exp"])
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    token_type = tokens["token_type"]

    %Credentials{
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires: !!exp_at,
      expires_at: exp_at,
      other: %{
        id_token: tokens["id_token"]
      }
    }
  end

  @doc """
  Returns an `Ueberauth.Auth.Extra` struct containing the raw tokens, claims, and opts.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        opts: conn.private.ueberauth_oidc_opts,
        claims: conn.private.ueberauth_oidc_claims,
        userinfo: conn.private[:ueberauth_oidc_userinfo]
      }
    }
  end

  @doc """
  Returns a `Ueberauth.Auth.Info` struct populated with the data returned from
  the userinfo endpoint.

  This information is also included in the `Ueberauth.Auth.Credentials` struct.
  """
  def info(conn) do
    userinfo = conn.private[:ueberauth_oidc_userinfo] || %{}
    claims = Map.merge(conn.private.ueberauth_oidc_claims, userinfo)

    %Info{}
    |> Map.from_struct()
    |> Enum.reduce(%Info{}, fn {k, v}, struct ->
      string_key = Atom.to_string(k)
      Map.put(struct, k, Map.get(claims, string_key, v))
    end)
  end

  defp set_error!(conn, key, message) do
    set_errors!(conn, [error(key, message)])
  end

  defp get_options!(conn) do
    defaults = %{
      module: OpenIDConnect,
      redirect_uri: callback_url(conn)
    }

    compile_opts = Map.new(options(conn))

    runtime_opts =
      Map.new((Application.get_env(:ueberauth, strategy(conn)) || [])[strategy_name(conn)] || %{})

    defaults
    |> Map.merge(compile_opts)
    |> Map.merge(runtime_opts)
  end

  defp expires_at(val) when is_binary(val) do
    val
    |> Integer.parse()
    |> elem(0)
    |> expires_at()
  end

  defp expires_at(expires_at), do: expires_at
end
