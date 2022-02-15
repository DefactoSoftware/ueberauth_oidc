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
    provider_id = conn |> get_options!() |> get_provider()
    params = params_from_conn(conn)

    try do
      uri = OpenIDConnect.authorization_uri(provider_id, params)
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
        provider_id = get_provider(opts)
        params = params_from_conn(conn, %{code: code})

        with {:ok, %{"access_token" => access_token, "id_token" => id_token} = tokens} <-
               OpenIDConnect.fetch_tokens(provider_id, params),
             {:ok, claims} <- OpenIDConnect.verify(provider_id, id_token) do
          conn
          |> put_private(:ueberauth_oidc_claims, claims)
          |> put_private(:ueberauth_oidc_tokens, tokens)
          |> put_private(:ueberauth_oidc_opts, opts)
          |> maybe_put_userinfo(opts, access_token)
        else
          {:error, type, reason} ->
            set_error!(conn, type, reason)

          {:error, reason} ->
            set_error!(conn, "error", reason)

          error ->
            set_error!(conn, "unknown_error", error)
        end
    end
  end

  defp params_from_conn(conn, params \\ %{}) do
    redirect_uri = conn |> get_options!() |> get_redirect_uri()

    %{redirect_uri: redirect_uri || callback_url(conn)}
    |> Map.merge(state_params(conn))
    |> Map.merge(params)
  end

  defp state_params(conn) do
    case conn.private[:ueberauth_state_param] do
      nil -> %{}
      state -> %{state: state}
    end
  end

  defp maybe_put_userinfo(conn, opts, access_token) do
    with true <- option(opts, :fetch_userinfo),
         provider_id <- get_provider(opts),
         {:ok, user_info} <- get_userinfo(provider_id, access_token) do
      put_private(conn, :ueberauth_oidc_user_info, user_info)
    else
      false -> conn
      e -> set_error!(conn, "error", "Error retrieving userinfo:" <> inspect(e))
    end
  end

  defp get_userinfo(provider_id, access_token) do
    headers = [Authorization: "Bearer #{access_token}", "Content-Type": "application/json"]

    with %{"userinfo_endpoint" => userinfo_endpoint} <-
           GenServer.call(:openid_connect, {:discovery_document, provider_id}),
         %HTTPoison.Response{body: body} <- http_client().get!(userinfo_endpoint, headers),
         userinfo_claims <- Jason.decode!(body) do
      user_info = for {k, v} <- userinfo_claims, do: {to_string(k), v}, into: %{}
      {:ok, user_info}
    end
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ueberauth_oidc_opts, nil)
    |> put_private(:ueberauth_oidc_claims, nil)
    |> put_private(:ueberauth_oidc_tokens, nil)
    |> put_private(:ueberauth_oidc_user_info, nil)
  end

  @doc """
  Returns the configured uid field from the id token.
  """
  def uid(conn) do
    private = conn.private

    with true <- option(private.ueberauth_oidc_opts, :fetch_userinfo),
         user_info <- option(private.ueberauth_oidc_opts, :userinfo_uid_field),
         true <- is_bitstring(user_info) do
      scrub_value(private.ueberauth_oidc_user_info[user_info])
    else
      _ ->
        uid_field = option(private.ueberauth_oidc_opts, :uid_field)
        scrub_value(private.ueberauth_oidc_claims[uid_field])
    end
  end

  @doc """
  Returns the credentials from the oidc response.

  `other` includes `provider` and `id_token`
  """
  def credentials(conn) do
    private = conn.private
    claims = conn.private.ueberauth_oidc_claims
    tokens = conn.private.ueberauth_oidc_tokens
    user_info = conn.private[:ueberauth_oidc_user_info]

    exp_at = claims["exp"] |> scrub_value() |> expires_at()
    access_token = tokens["access_token"] |> scrub_value()
    token_type = tokens["token_type"] |> scrub_value()

    %Credentials{
      token: access_token,
      token_type: token_type,
      expires: !!exp_at,
      expires_at: exp_at,
      other: %{
        user_info: user_info,
        provider: get_provider(private.ueberauth_oidc_opts)
      }
    }
  end

  @doc """
  Returns an `Ueberauth.Auth.Extra` struct containing the raw token map
  obtained from `:oidcc`.

  Since `:oidcc` is an erlang library, empty values in the map are
  represented by `:undefined` or `:none`, not `nil`.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        claims: conn.private.ueberauth_oidc_claims,
        tokens: conn.private.ueberauth_oidc_tokens,
        opts: conn.private.ueberauth_oidc_opts
      }
    }
  end

  @doc """
  Returns a `Ueberauth.Auth.Info` struct populated with the data returned from
  the userinfo endpoint.

  This information is also included in the `Ueberauth.Auth.Credentials` struct.
  """
  def info(conn) do
    with user_info when not is_nil(user_info) <- conn.private[:ueberauth_oidc_user_info] do
      %Info{}
      |> Map.from_struct()
      |> Enum.reduce(%Info{}, fn {k, v}, struct ->
        string_key = Atom.to_string(k)
        Map.put(struct, k, Map.get(user_info, string_key, v))
      end)
    else
      _ -> %Info{}
    end
  end

  defp scrub_value(:undefined), do: nil
  defp scrub_value(:none), do: nil
  defp scrub_value(val), do: val

  defp set_error!(conn, key, message) do
    set_errors!(conn, [error(key, message)])
  end

  defp get_provider(opts), do: option(opts, :provider)
  defp get_redirect_uri(opts), do: option(opts, :redirect_uri)
  defp option(opts, key), do: Keyword.get(opts, key)

  defp get_options!(conn) do
    oidc_opts = Application.get_env(:ueberauth, __MODULE__, [])
    supplied_defaults = conn |> options() |> Keyword.get(:default, [])

    # untrusted input
    provider_id = conn.params["oidc_provider"] || Keyword.fetch!(supplied_defaults, :provider)

    provider_opts =
      case is_atom(provider_id) do
        true ->
          Keyword.get(oidc_opts, provider_id, [])

        false ->
          Enum.find_value(oidc_opts, [], &find_provider_opts(&1, provider_id))
      end

    default_options()
    |> Keyword.merge(supplied_defaults)
    |> Keyword.merge(provider_opts)
    |> Keyword.put(:provider, provider_id)
  end

  defp find_provider_opts({key, val}, provider_id) do
    if provider_id == to_string(key), do: val
  end

  defp expires_at(nil), do: nil

  defp expires_at(val) when is_binary(val) do
    val
    |> Integer.parse()
    |> elem(0)
    |> expires_at()
  end

  defp expires_at(expires_in), do: unix_now() + expires_in

  defp unix_now do
    {mega, sec, _micro} = :os.timestamp()
    mega * 1_000_000 + sec
  end

  defp http_client do
    Application.get_env(:ueberauth_oidc, :http_client, HTTPoison)
  end
end
