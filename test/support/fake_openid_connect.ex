defmodule FakeOpenIDConnect do
  @moduledoc """
  Fake implementation of the `OpenIDConnect` module to support testing.
  """

  def request_url do
    "https://oidc.example/request"
  end

  def callback_code do
    "valid_code"
  end

  def authorization_uri(opts, params \\ %{})

  def authorization_uri(%{discovery_document_uri: _} = opts, params) do
    params =
      Map.merge(
        %{
          client_id: opts.client_id,
          redirect_uri: opts.redirect_uri,
          response_type: opts.response_type,
          scope: opts.scope
        },
        params
      )

    query = URI.encode_query(params)

    {:ok, "#{request_url()}?#{query}"}
  end

  def authorization_uri(_opts, _params) do
    {:error, :missing_discovery_document_uri}
  end

  def fetch_tokens(opts, params)

  def fetch_tokens(%{:_fetch_tokens => false}, _) do
    {:error, :no_tokens}
  end

  def fetch_tokens(%{discovery_document_uri: _, client_secret: "secret_value"}, params) do
    if Map.get(params, :code) == callback_code() do
      {:ok,
       %{
         "access_token" => "access_token_value",
         "id_token" => "id_token_value",
         "refresh_token" => "refresh_token_value",
         "token_type" => "Bearer"
       }}
    else
      {:error, :invalid_code}
    end
  end

  def fetch_tokens(_opts, _params) do
    {:error, :no_tokens}
  end

  def verify(opts, id_token)

  def verify(%{:_verify_tokens => false}, _) do
    {:error, :invalid}
  end

  def verify(%{discovery_document_uri: _}, "id_token_value") do
    {:ok,
     %{
       # Sat Nov 20 12:46:40 EST 2286
       "exp" => 10_000_000_000,
       "sub" => "sub_value",
       "email" => "email_value"
     }}
  end

  def verify(_opts, _params) do
    {:error, :invalid}
  end

  def fetch_userinfo(opts, access_token)

  def fetch_userinfo(%{:_fetch_userinfo => false}, _access_token) do
    {:error, :invalid}
  end

  def fetch_userinfo(
        %{discovery_document_uri: _, client_secret: "secret_value"},
        "access_token_value"
      ) do
    {:ok,
     %{
       "sub" => "userinfo_sub",
       "name" => "Full Name",
       "first_name" => "First",
       "last_name" => "Last",
       "nickname" => "Nickname",
       "email" => "test@email.example",
       "picture" => "http://photo.example",
       "phone_number" => "phone_number_value",
       "birthdate" => "1970-01-01",
       "profile" => "http://profile.example",
       "website" => "http://website.example"
     }}
  end

  def fetch_userinfo(_opts, _access_token) do
    {:error, :invalid}
  end
end
