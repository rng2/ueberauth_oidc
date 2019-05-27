defmodule Ueberauth.Strategy.OIDCTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.OIDC

  @local_endpoint "https://oidc.local/callback"

  describe "OIDC Strategy" do
    setup_with_mocks [
      {:oidcc_session, [],
       [
         close: fn _ -> :ok end,
         get_provider: fn _ -> {:ok, "test_provider"} end,
         get_pkce: fn sid -> {:ok, sid} end,
         get_nonce: fn sid -> {:ok, sid} end,
         get_scopes: fn sid -> {:ok, sid} end
       ]},
      {:oidcc_session_mgr, [],
       [new_session: fn sid -> {:ok, sid} end, get_session: fn sid -> {:ok, sid} end]},
      {Ueberauth.Strategy.Helpers, [:passtrough],
       [
         options: fn _ -> [] end,
         set_errors!: fn _, _ -> nil end,
         error: fn key, msg -> {key, msg} end,
         redirect!: fn _, url -> url end
       ]}
    ] do
      :ok
    end

    test "Handles an OIDC request" do
      with_mock :oidcc,
        get_openid_provider_info: fn _ -> {:ok, %{ready: true}} end,
        create_redirect_for_session: fn _ -> {:ok, @local_endpoint} end do
        request =
          OIDC.handle_request!(%Plug.Conn{
            params: %{"oidc_provider" => "test_provider"},
            private: %{ueberauth_request_options: %{options: []}}
          })

        assert request =~ @local_endpoint
      end
    end

    test "Handle callback from provider with a session_id, validate tokens" do
      with_mock :oidcc,
        retrieve_and_validate_token: fn _, _, _ ->
          {:ok, %{id: %{claims: :claims}, access: %{hash: :verified}}}
        end do
        callback =
          OIDC.handle_callback!(%Plug.Conn{
            params: %{"state" => 1234, "code" => 1234, "oidc_provider" => "test_provider"},
            private: %{ueberauth_request_options: %{options: []}}
          })

        assert %Plug.Conn{
                 private: %{
                   ueberauth_oidc_opts: [provider: "test_provider", uid_field: _],
                   ueberauth_oidc_tokens: %{access: _, id: _}
                 }
               } = callback
      end
    end

    test "Handle callback from provider with a missing state" do
      OIDC.handle_callback!(%Plug.Conn{params: %{}})

      assert_called(
        Ueberauth.Strategy.Helpers.set_errors!(:_, [
          {"error", "Query string does not contain field 'state'"}
        ])
      )
    end

    test "Handle callback from provider with an error retrieving session" do
      with_mock :oidcc_session_mgr, get_session: fn _ -> {:error, "some message"} end do
        OIDC.handle_callback!(%Plug.Conn{params: %{"state" => 1234}})

        assert_called(
          Ueberauth.Strategy.Helpers.set_errors!(:_, [{"oidcc_error", "some message"}])
        )
      end
    end

    test "Handle callback from provider with an error response" do
      OIDC.handle_callback!(%Plug.Conn{params: %{"state" => 1234, "error" => "error message"}})

      assert_called(
        Ueberauth.Strategy.Helpers.set_errors!(:_, [{"oidc_provider_error", "error message"}])
      )
    end

    test "Handle callback from provider with a session_id, invalid token" do
      with_mock :oidcc, retrieve_and_validate_token: fn _, _, _ -> {:error, :invalid} end do
        OIDC.handle_callback!(%Plug.Conn{
          params: %{"state" => 1234, "code" => 1234, "oidc_provider" => "test_provider"},
          private: %{ueberauth_request_options: %{options: []}}
        })

        assert_called(Ueberauth.Strategy.Helpers.set_errors!(:_, [{"oidcc_error", "invalid"}]))
      end
    end

    test "Handle callback from provider with a session_id, missing token" do
      with_mock :oidcc, retrieve_and_validate_token: fn _, _, _ -> {:error, %{}} end do
        OIDC.handle_callback!(%Plug.Conn{
          params: %{"state" => 1234, "code" => 1234, "oidc_provider" => "test_provider"},
          private: %{ueberauth_request_options: %{options: []}}
        })

        assert_called(
          Ueberauth.Strategy.Helpers.set_errors!(:_, [
            {"oidcc_error", "Failed to retrieve and validate tokens"}
          ])
        )
      end
    end

    test "Handle callback from provider with a session_id, without claims" do
      with_mock :oidcc,
        retrieve_and_validate_token: fn _, _, _ ->
          {:ok, %{id: %{claims: :undefined}, access: %{hash: :verified}}}
        end do
        OIDC.handle_callback!(%Plug.Conn{
          params: %{"state" => 1234, "code" => 1234, "oidc_provider" => "test_provider"},
          private: %{ueberauth_request_options: %{options: []}}
        })

        assert_called(
          Ueberauth.Strategy.Helpers.set_errors!(:_, [
            {"oidcc_error", "Failed to extract claims from id_token"}
          ])
        )
      end
    end

    test "Handle callback from provider with a session_id, with invalid hash" do
      with_mock :oidcc,
        retrieve_and_validate_token: fn _, _, _ ->
          {:ok, %{id: %{claims: :claims}, access: %{hash: :hash}}}
        end do
        OIDC.handle_callback!(%Plug.Conn{
          params: %{"state" => 1234, "code" => 1234, "oidc_provider" => "test_provider"},
          private: %{ueberauth_request_options: %{options: []}}
        })

        assert_called(
          Ueberauth.Strategy.Helpers.set_errors!(:_, [
            {"oidcc_error", "Failed to validate id_token hash"}
          ])
        )
      end
    end

    test "handle cleanup of uberauth values in the conn" do
      conn_with_values = %Plug.Conn{
        private: %{ueberauth_oidc_opts: :some_value, uebrauth_oidc_tokens: :another_value}
      }

      assert %Plug.Conn{private: %{ueberauth_oidc_opts: nil, ueberauth_oidc_tokens: nil}} =
               OIDC.handle_cleanup!(conn_with_values)
    end

    test "Get the uid from the conn" do
      conn = %Plug.Conn{
        private: %{
          ueberauth_oidc_opts: [uid_field: :sub],
          ueberauth_oidc_tokens: %{id: %{claims: %{sub: "some_uid"}}}
        }
      }

      assert OIDC.uid(conn) == "some_uid"
    end

    test "Return nil when uid_field is invalid" do
      conn = %Plug.Conn{
        private: %{
          ueberauth_oidc_opts: [uid_field: :uid],
          ueberauth_oidc_tokens: %{id: %{claims: %{sub: "some_uid"}}}
        }
      }

      assert OIDC.uid(conn) == nil
    end

    test "Get credentials from the conn" do
      conn = %Plug.Conn{
        private: %{
          ueberauth_oidc_tokens: %{
            id: %{token: "id_token"},
            access: %{expires: "1234", token: "access_token"},
            refresh: %{token: "refresh_token"},
            scope: %{list: [:some_scope]}
          },
          ueberauth_oidc_opts: [provider: "some_provider"]
        }
      }

      assert %{
               expires: true,
               other: %{id_token: "id_token", provider: "some_provider"},
               refresh_token: "refresh_token",
               scopes: [:some_scope],
               token: "access_token",
               token_type: "Bearer"
             } = OIDC.credentials(conn)
    end

    test "Puts the raw token map in the Extra struct" do
      assert OIDC.extra(%Plug.Conn{private: %{ueberauth_oidc_tokens: %{some_token: :some_value}}}) ==
               %Ueberauth.Auth.Extra{raw_info: %{tokens: %{some_token: :some_value}}}
    end
  end
end
