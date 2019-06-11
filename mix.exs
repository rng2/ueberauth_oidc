defmodule UeberauthOIDC.Mixfile do
  use Mix.Project

  @version "0.0.1"

  def project do
    [
      app: :ueberauth_oidc,
      version: @version,
      name: "Ueberauth OIDC",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      description: description(),
      deps: deps(),
      dialyzer: [
        plt_add_apps: [:plug],
        flags: [
          :unmatched_returns,
          :error_handling,
          :race_conditions,
          :underspecs
        ]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 0.5", only: :dev, runtime: false},
      {:ex_doc, "~> 0.18", only: :dev, runtime: false},
      {:jsone, "~> 1.4", override: true},
      {:mock, "~> 0.3.0", only: :test},
      {:oidcc, "~> 1.8"},
      {:ueberauth, "~> 0.6"}
    ]
  end

  defp description do
    "An Ueberauth strategy for generic OpenID Connect authentication."
  end
end
