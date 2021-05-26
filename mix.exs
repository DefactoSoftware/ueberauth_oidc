defmodule UeberauthOIDC.Mixfile do
  use Mix.Project

  def project do
    [
      app: :ueberauth_oidc,
      name: "Ueberauth OIDC",
      version: "0.1.0",
      elixir: "~> 1.7",
      description: """
      An Ueberauth strategy for generic OpenID Connect authentication.
      """,
      package: package(),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp package do
    [
      maintainers: ["Rick Littel - @Kuret"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/DefactoSoftware/ueberauth_oidc"}
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.5", only: [:dev, :test]},
      {:ex_doc, "~> 0.24", only: [:dev, :test]},
      {:jose, "~> 1.11", override: true},
      {:httpoison, "~> 1.8", override: true},
      {:mock, "~> 0.3", only: :test},
      {:openid_connect, "~> 0.2.2"},
      {:plug, "~> 1.11"},
      {:ueberauth, "~> 0.6"}
    ]
  end
end
