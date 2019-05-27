defmodule UeberauthOIDCTest do
  use ExUnit.Case

  import Mock

  @config local_endpoint: "https://local.com/oidc/callback",
          provider1: [
            issuer_or_config_endpoint: "https://provider.com/.well-known/openid-configuration",
            client_id: "client_id",
            client_secret: "client_secret",
            request_scopes: ["openid"]
          ],
          provider2: [
            issuer_or_config_endpoint: "https://provider2.com/.well-known/openid-configuration",
            client_id: "client2_id",
            client_secret: "client2_secret",
            request_scopes: ["openid"]
          ]

  describe "UeberauthOIDC" do
    test "add configured providers on init" do
      with_mock Application, get_env: fn _, _ -> @config end do
        UeberauthOIDC.init!()

        assert {:ok, [{"provider1", _}, {"provider2", _}]} = :oidcc.get_openid_provider_list()

        assert {:ok, %{client_id: "client_id", issuer: "https://provider.com"}} =
                 :oidcc.get_openid_provider_info("provider1")

        assert {:ok, %{client_id: "client2_id", issuer: "https://provider2.com"}} =
                 :oidcc.get_openid_provider_info("provider2")
      end
    end
  end
end
