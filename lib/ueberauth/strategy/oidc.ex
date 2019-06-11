defmodule Ueberauth.Strategy.OIDC do
  @moduledoc """
  OIDC Strategy for Ueberauth.
  """

  use Ueberauth.Strategy, uid_field: :sub

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  @oidcc_error "oidcc_error"

  @doc """
  Handles the initial authentication request.
  """
  def handle_request!(conn) do
    opts = get_options!(conn)

    {:ok, provider_id} = get_and_validate_provider(opts)
    {:ok, session} = :oidcc_session_mgr.new_session(provider_id)

    try do
      {:ok, url} = :oidcc.create_redirect_for_session(session)
      redirect!(conn, url)
    rescue
      e ->
        stacktrace = System.stacktrace()
        :oidcc_session.close(session)
        reraise e, stacktrace
    end
  end

  @doc """
  Handles the callback from the oidc provider.
  """
  def handle_callback!(conn) do
    case conn.params["state"] do
      nil ->
        set_error!(conn, "error", "Query string does not contain field 'state'")

      session_id ->
        case :oidcc_session_mgr.get_session(session_id) do
          {:error, reason} -> set_error!(conn, @oidcc_error, reason)
          {:ok, session} -> handle_callback!(conn, session)
        end
    end
  end

  defp handle_callback!(conn, session) do
    case conn.params["error"] do
      nil ->
        opts = get_options!(conn)

        provider_id = get_provider(opts)
        {:ok, ^provider_id} = :oidcc_session.get_provider(session)
        {:ok, pkce} = :oidcc_session.get_pkce(session)
        {:ok, nonce} = :oidcc_session.get_nonce(session)
        {:ok, scope} = :oidcc_session.get_scopes(session)
        config = %{nonce: nonce, pkce: pkce, scope: scope}
        code = conn.params["code"]

        case :oidcc.retrieve_and_validate_token(code, provider_id, config) do
          {:ok, tokens} ->
            validate_tokens(conn, opts, tokens)

          {:error, e} when is_atom(e) or is_binary(e) ->
            set_error!(conn, @oidcc_error, to_string(e))

          _ ->
            set_error!(conn, @oidcc_error, "Failed to retrieve and validate tokens")
        end

      message ->
        set_error!(conn, "oidc_provider_error", message)
    end
  after
    :oidcc_session.close(session)
  end

  defp validate_tokens(conn, opts, tokens) do
    cond do
      tokens[:id][:claims] == :undefined ->
        set_error!(conn, @oidcc_error, "Failed to extract claims from id_token")

      tokens[:access][:hash] not in [:verified, :no_hash] ->
        set_error!(conn, @oidcc_error, "Failed to validate id_token hash")

      true ->
        conn
        |> put_private(:ueberauth_oidc_opts, opts)
        |> put_private(:ueberauth_oidc_tokens, tokens)
        |> maybe_put_userinfo(opts)
    end
  end

  defp maybe_put_userinfo(%{private: %{ueberauth_oidc_tokens: tokens}} = conn, opts) do
    with true <- option(opts, :fetch_userinfo),
         provider <- get_provider(opts),
         token <- scrub_value(tokens[:access][:token]),
         {:ok, user_info} <- :oidcc.retrieve_user_info(token, provider) do
      user_info = for {k, v} <- user_info, do: {to_string(k), v}, into: %{}
      put_private(conn, :ueberauth_oidc_user_info, user_info)
    else
      _ -> conn
    end
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ueberauth_oidc_opts, nil)
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
        scrub_value(private.ueberauth_oidc_tokens[:id][:claims][uid_field])
    end
  end

  @doc """
  Returns the credentials from the oidc response.

  `other` includes `provider` and `id_token`
  """
  def credentials(conn) do
    private = conn.private
    tokens = conn.private.ueberauth_oidc_tokens
    user_info = conn.private[:ueberauth_oidc_user_info]

    exp_at =
      tokens[:access][:expires]
      |> scrub_value()
      |> expires_at()

    %Credentials{
      token: scrub_value(tokens[:access][:token]),
      refresh_token: scrub_value(tokens[:refresh][:token]),
      token_type: "Bearer",
      expires: !!exp_at,
      expires_at: exp_at,
      scopes: scrub_value(tokens[:scope][:list]),
      other: %{
        user_info: user_info,
        provider: get_provider(private.ueberauth_oidc_opts),
        id_token: scrub_value(tokens[:id][:token])
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
        tokens: conn.private.ueberauth_oidc_tokens
      }
    }
  end

  @doc """
  Returns an empty `Ueberauth.Auth.Info` struct.

  Use information included in the `Ueberauth.Auth.Credentials` and
  `Ueberauth.Auth.Extra` structs instead.
  """
  def info(_conn) do
    %Info{}
  end

  defp scrub_value(:undefined), do: nil
  defp scrub_value(:none), do: nil
  defp scrub_value(val), do: val

  defp set_error!(conn, key, message) do
    set_errors!(conn, [error(key, message)])
  end

  defp get_and_validate_provider(opts) do
    provider_id = get_provider(opts)

    case :oidcc.get_openid_provider_info(provider_id) do
      {:ok, %{ready: true}} ->
        {:ok, provider_id}

      {:ok, %{ready: false}} ->
        {:provider_not_ready, provider_id}

      _ ->
        {:bad_provider, provider_id}
    end
  end

  defp get_provider(opts), do: option(opts, :provider)

  defp option(opts, key), do: Keyword.get(opts, key)

  defp get_options!(conn) do
    all_opts = options(conn)
    supplied_defaults = Keyword.get(all_opts, :default, [])

    # untrusted input
    provider_id = conn.params["oidc_provider"] || Keyword.fetch!(supplied_defaults, :provider)

    provider_opts =
      case is_atom(provider_id) do
        true ->
          Keyword.get(all_opts, provider_id, [])

        false ->
          Enum.find_value(all_opts, [], fn {key, val} ->
            if provider_id == to_string(key), do: val
          end)
      end

    default_options()
    |> Keyword.merge(supplied_defaults)
    |> Keyword.merge(provider_opts)
    |> Keyword.put(:provider, to_string(provider_id))
  end

  defp expires_at(nil), do: nil

  defp expires_at(val) when is_binary(val) do
    val
    |> Integer.parse()
    |> elem(0)
    |> expires_at()
  end

  defp expires_at(expires_in), do: unix_now() + expires_in

  defp unix_now() do
    {mega, sec, _micro} = :os.timestamp()
    mega * 1_000_000 + sec
  end
end
