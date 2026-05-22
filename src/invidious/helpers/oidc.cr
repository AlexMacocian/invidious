require "jwt"
require "json"
require "http/client"

module Invidious::OIDCHelper
  extend self
  DISCOVERY_CACHE = {} of String => JSON::Any

  def get_provider(key)
    if provider = CONFIG.oidc[key]?
      provider
    else
      raise Exception.new("Invalid OIDC Provider: " + key)
    end
  end

  def get_host_url
    if CONFIG.domain && CONFIG.external_port
      port_part = CONFIG.external_port == 443 || CONFIG.external_port == 80 ? "" : ":#{CONFIG.external_port}"
      scheme = CONFIG.https_only || CONFIG.external_port == 443 ? "https" : "http"
      "#{scheme}://#{CONFIG.domain}#{port_part}"
    elsif CONFIG.domain
      scheme = CONFIG.https_only ? "https" : "http"
      "#{scheme}://#{CONFIG.domain}"
    else
      raise Exception.new("Missing domain configuration for OIDC")
    end
  end

  def get_discovery_document(provider : OIDCConfig)
    cache_key = provider.issuer
    
    if cached = DISCOVERY_CACHE[cache_key]?
      return cached
    end

    discovery_url = provider.discovery_endpoint || "#{provider.issuer}/.well-known/openid-configuration"
    uri = URI.parse(discovery_url)
    
    client = HTTP::Client.new(uri.host.not_nil!, port: uri.port, tls: uri.scheme == "https")
    
    # Follow redirects manually (up to 3 redirects)
    current_path = uri.path || "/"
    if query = uri.query
      current_path += "?" + query
    end
    
    3.times do
      response = client.get(current_path)
      
      case response.status_code
      when 200
        discovery_doc = JSON.parse(response.body)
        DISCOVERY_CACHE[cache_key] = discovery_doc
        client.close
        return discovery_doc
      when 301, 302, 303, 307, 308
        location = response.headers["Location"]?
        if location
          if location.starts_with?("http")
            # Absolute URL redirect - need new client
            client.close
            new_uri = URI.parse(location)
            client = HTTP::Client.new(new_uri.host.not_nil!, port: new_uri.port, tls: new_uri.scheme == "https")
            current_path = new_uri.path || "/"
            if query = new_uri.query
              current_path += "?" + query
            end
          else
            # Relative redirect
            current_path = location
          end
        else
          client.close
          raise Exception.new("Redirect without Location header")
        end
      else
        LOGGER.error("OIDC Discovery: Failed to fetch from #{discovery_url}")
        LOGGER.error("OIDC Discovery: Response code: #{response.status_code}")
        LOGGER.error("OIDC Discovery: Response body: #{response.body}")
        client.close
        raise Exception.new("Failed to fetch OIDC discovery document from #{discovery_url}: #{response.status_code}")
      end
    end
    
    client.close
    raise Exception.new("Too many redirects when fetching OIDC discovery document")
  end

  def get_authorization_url(key : String, state : String, nonce : String)
    provider = get_provider(key)
    discovery_doc = get_discovery_document(provider)
    
    auth_endpoint = provider.auth_endpoint || discovery_doc["authorization_endpoint"].as_s
    redirect_uri = "#{get_host_url}/login/oidc/#{key}/callback"
    
    params = HTTP::Params.build do |form|
      form.add "response_type", "code"
      form.add "client_id", provider.client_id
      form.add "redirect_uri", redirect_uri
      form.add "scope", provider.scopes.join(" ")
      form.add "state", state
      form.add "nonce", nonce
    end

    "#{auth_endpoint}?#{params}"
  end

  def exchange_code_for_tokens(key : String, authorization_code : String)
    provider = get_provider(key)
    discovery_doc = get_discovery_document(provider)
    
    token_endpoint = provider.token_endpoint || discovery_doc["token_endpoint"].as_s
    redirect_uri = "#{get_host_url}/login/oidc/#{key}/callback"
    
    uri = URI.parse(token_endpoint)
    client = HTTP::Client.new(uri.host.not_nil!, port: uri.port, tls: uri.scheme == "https")
    
    form_data = HTTP::Params.build do |form|
      form.add "grant_type", "authorization_code"
      form.add "code", authorization_code
      form.add "redirect_uri", redirect_uri
      form.add "client_id", provider.client_id
      form.add "client_secret", provider.client_secret
    end

    headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
    path = uri.path || "/"
    response = client.post(path, headers: headers, body: form_data.to_s)
    client.close

    if response.status_code != 200
      raise Exception.new("Token exchange failed: #{response.status_code} - #{response.body}")
    end

    JSON.parse(response.body)
  end

  def get_jwks(provider : OIDCConfig)
    discovery_doc = get_discovery_document(provider)
    jwks_uri = provider.jwks_uri || discovery_doc["jwks_uri"].as_s
    
    uri = URI.parse(jwks_uri)
    client = HTTP::Client.new(uri.host.not_nil!, port: uri.port, tls: uri.scheme == "https")
    response = client.get(uri.path || "/")
    client.close

    if response.status_code != 200
      raise Exception.new("Failed to fetch JWKS: #{response.status_code}")
    end

    JSON.parse(response.body)
  end

  def verify_id_token(key : String, id_token : String, nonce : String)
    provider = get_provider(key)
    
    # TODO: validate jks signature
    token_parts = id_token.split(".")
    if token_parts.size != 3
      raise Exception.new("Invalid JWT format")
    end

    payload_base64 = token_parts[1]
    while payload_base64.size % 4 != 0
      payload_base64 += "="
    end
    
    payload_json = Base64.decode_string(payload_base64)
    payload = JSON.parse(payload_json)

    now = Time.utc.to_unix
    
    if payload["exp"]? && payload["exp"].as_i64 < now
      raise Exception.new("Token expired")
    end

    if payload["iss"]?
      token_issuer = payload["iss"].as_s
      if token_issuer != provider.issuer
        LOGGER.error("OIDC Token Validation: Issuer mismatch")
        LOGGER.error("OIDC Token Validation: Expected issuer: #{provider.issuer}")
        LOGGER.error("OIDC Token Validation: Token issuer: #{token_issuer}")
        raise Exception.new("Invalid issuer - expected: #{provider.issuer}, got: #{token_issuer}")
      end
    end

    if payload["aud"]? && payload["aud"].as_s != provider.client_id
      raise Exception.new("Invalid audience")
    end

    if payload["nonce"]? && payload["nonce"].as_s != nonce
      raise Exception.new("Invalid nonce")
    end

    payload
  end

  def get_userinfo(key : String, access_token : String)
    provider = get_provider(key)
    discovery_doc = get_discovery_document(provider)
    
    userinfo_endpoint = provider.userinfo_endpoint || discovery_doc["userinfo_endpoint"]?.try(&.as_s)
    
    return nil unless userinfo_endpoint

    uri = URI.parse(userinfo_endpoint)
    client = HTTP::Client.new(uri.host.not_nil!, port: uri.port, tls: uri.scheme == "https")
    headers = HTTP::Headers{"Authorization" => "Bearer #{access_token}"}
    response = client.get(uri.path || "/", headers: headers)
    client.close

    if response.status_code != 200
      raise Exception.new("Failed to fetch userinfo: #{response.status_code}")
    end

    JSON.parse(response.body)
  end

  def extract_user_email(key : String, id_token_payload : JSON::Any, userinfo : JSON::Any?)
    provider = get_provider(key)
    field = provider.field

    # First try to get configured field from ID token and fallback to userinfo
    if email = id_token_payload[field]?
      return email.as_s
    end

    if userinfo && (email = userinfo[field]?)
      return email.as_s
    end

    raise Exception.new("Could not extract email from OIDC response")
  end
end