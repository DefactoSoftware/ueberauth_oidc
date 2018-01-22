defmodule UeberauthOIDC do
  @moduledoc """
  Main module.
  """

  @doc """
  Initializes the configured oidc providers.
  """
  @spec init!() :: :ok
  def init!() do
    {local_endpoint, config} =
      Application.get_env(:ueberauth, UeberauthOIDC)
      |> Keyword.pop(:local_endpoint)

    :ok = Enum.each(config, &add_provider!(&1, local_endpoint))
  end

  defp add_provider!({id, config}, local_endpoint) do
    {config_endpoint, config} =
      config
      |> Enum.into(%{})
      |> Map.pop(:issuer_or_config_endpoint)

    config = Map.put_new(config, :id, to_string(id))
    {:ok, _, _provider} = :oidcc.add_openid_provider(config_endpoint, local_endpoint, config)
  end
end
