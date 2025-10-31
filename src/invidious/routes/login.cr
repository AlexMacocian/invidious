{% skip_file if flag?(:api_only) %}

module Invidious::Routes::Login
  def self.login_page(env)
    locale = env.get("preferences").as(Preferences).locale

    user = env.get? "user"

    referer = get_referer(env, "/feed/subscriptions")

    return env.redirect referer if user

    if !CONFIG.login_enabled
      return error_template(400, "Login has been disabled by administrator.")
    end

    email = nil
    password = nil
    captcha = nil

    account_type = env.params.query["type"]?
    account_type ||= ""

    if CONFIG.auth_type.size == 0
      return error_template(401, "No authentication backend enabled.")
    elsif CONFIG.auth_type.find(&.== account_type).nil? && CONFIG.auth_type.size == 1
      account_type = CONFIG.auth_type[0]
    end

    captcha_type = env.params.query["captcha"]?
    captcha_type ||= "image"

    templated "user/login"
  end

  def self.login(env)
    locale = env.get("preferences").as(Preferences).locale

    referer = get_referer(env, "/feed/subscriptions")

    if !CONFIG.login_enabled
      return error_template(403, "Login has been disabled by administrator.")
    end

    # https://stackoverflow.com/a/574698
    email = env.params.body["email"]?.try &.downcase.byte_slice(0, 254)
    password = env.params.body["password"]?

    account_type = env.params.query["type"]?
    account_type ||= "invidious"

    case account_type
    when "oidc"
      provider_k = env.params.body["provider"]
      state = Base64.urlsafe_encode(Random::Secure.random_bytes(32))
      nonce = Base64.urlsafe_encode(Random::Secure.random_bytes(32))

      env.response.cookies["OIDC_STATE"] = HTTP::Cookie.new(
        name: "OIDC_STATE",
        value: "#{state}:#{nonce}:#{provider_k}",
        path: "/",
        expires: Time.utc + 10.minutes,
        secure: CONFIG.https_only == true,
        http_only: true
      )
      
      authorization_url = OIDCHelper.get_authorization_url(provider_k, state, nonce)
      env.redirect authorization_url
    when "invidious"
      if email.nil? || email.empty?
        return error_template(401, "User ID is a required field")
      end

      if password.nil? || password.empty?
        return error_template(401, "Password is a required field")
      end

      user = Invidious::Database::Users.select(email: email)

      if user
        if Crypto::Bcrypt::Password.new(user.password.not_nil!).verify(password.byte_slice(0, 55))
          sid = Base64.urlsafe_encode(Random::Secure.random_bytes(32))
          Invidious::Database::SessionIDs.insert(sid, email)

          env.response.cookies["SID"] = Invidious::User::Cookies.sid(CONFIG.domain, sid)
        else
          return error_template(401, "Wrong username or password")
        end

        # Since this user has already registered, we don't want to overwrite their preferences
        if env.request.cookies["PREFS"]?
          cookie = env.request.cookies["PREFS"]
          cookie.expires = Time.utc(1990, 1, 1)
          env.response.cookies << cookie
        end
      else
        if !CONFIG.registration_enabled
          return error_template(400, "Registration has been disabled by administrator.")
        end

        if password.empty?
          return error_template(401, "Password cannot be empty")
        end

        # See https://security.stackexchange.com/a/39851
        if password.bytesize > 55
          return error_template(400, "Password cannot be longer than 55 characters")
        end

        password = password.byte_slice(0, 55)

        if CONFIG.captcha_enabled
          answer = env.params.body["answer"]?

          account_type = "invidious"
          captcha = Invidious::User::Captcha.generate_image(HMAC_KEY)

          tokens = env.params.body.select { |k, _| k.match(/^token\[\d+\]$/) }.map { |_, v| v }

          if answer
            answer = answer.lstrip('0')
            answer = OpenSSL::HMAC.hexdigest(:sha256, HMAC_KEY, answer)

            begin
              validate_request(tokens[0], answer, env.request, HMAC_KEY, locale)
            rescue ex
              return error_template(400, ex)
            end
          else
            return templated "user/login"
          end
        end

        sid = Base64.urlsafe_encode(Random::Secure.random_bytes(32))
        user, sid = create_user(sid, email, password)

        if language_header = env.request.headers["Accept-Language"]?
          if language = ANG.language_negotiator.best(language_header, LOCALES.keys)
            user.preferences.locale = language.header
          end
        end

        Invidious::Database::Users.insert(user)
        Invidious::Database::SessionIDs.insert(sid, email)

        view_name = "subscriptions_#{sha256(user.email)}"
        PG_DB.exec("CREATE MATERIALIZED VIEW #{view_name} AS #{MATERIALIZED_VIEW_SQL.call(user.email)}")

        env.response.cookies["SID"] = Invidious::User::Cookies.sid(CONFIG.domain, sid)

        if env.request.cookies["PREFS"]?
          user.preferences = env.get("preferences").as(Preferences)
          Invidious::Database::Users.update_preferences(user)

          cookie = env.request.cookies["PREFS"]
          cookie.expires = Time.utc(1990, 1, 1)
          env.response.cookies << cookie
        end
      end

      env.redirect referer
    else
      env.redirect referer
    end
  end

  def self.signout(env)
    locale = env.get("preferences").as(Preferences).locale

    user = env.get? "user"
    sid = env.get? "sid"
    referer = get_referer(env)

    if !user
      return env.redirect referer
    end

    user = user.as(User)
    sid = sid.as(String)
    token = env.params.body["csrf_token"]?

    begin
      validate_request(token, sid, env.request, HMAC_KEY, locale)
    rescue ex
      return error_template(400, ex)
    end

    Invidious::Database::SessionIDs.delete(sid: sid)

    env.request.cookies.each do |cookie|
      cookie.expires = Time.utc(1990, 1, 1)
      env.response.cookies << cookie
    end

    env.redirect referer
  end

  def self.oidc_callback(env)
    locale = env.get("preferences").as(Preferences).locale
    referer = get_referer(env, "/feed/subscriptions")

    authorization_code = env.params.query["code"]?
    state = env.params.query["state"]?
    provider_k = env.params.url["provider"]

    if authorization_code.nil?
      return error_template(403, "Missing authorization code")
    end

    if state.nil?
      return error_template(403, "Missing state parameter")
    end

    state_cookie = env.request.cookies["OIDC_STATE"]?
    if !state_cookie
      return error_template(403, "Missing state cookie")  
    end

    state_parts = state_cookie.value.split(":")
    if state_parts.size != 3 || state_parts[0] != state || state_parts[2] != provider_k
      return error_template(403, "Invalid state")
    end

    stored_state, nonce, stored_provider = state_parts

    env.response.cookies["OIDC_STATE"] = HTTP::Cookie.new(
      name: "OIDC_STATE",
      value: "",
      path: "/",
      expires: Time.utc(1990, 1, 1)
    )

    begin
      token_response = OIDCHelper.exchange_code_for_tokens(provider_k, authorization_code)
      id_token = token_response["id_token"]?.try(&.as_s)
      access_token = token_response["access_token"]?.try(&.as_s)
      
      if !id_token
        return error_template(500, "No ID token received")
      end

      id_token_payload = OIDCHelper.verify_id_token(provider_k, id_token, nonce)
      userinfo = nil
      if access_token
        userinfo = OIDCHelper.get_userinfo(provider_k, access_token)
      end

      email = OIDCHelper.extract_user_email(provider_k, id_token_payload, userinfo)

      if user = Invidious::Database::Users.select(email: email)
        if CONFIG.auth_enforce_source && user.password != ("oidc:" + provider_k)
          return error_template(401, "Wrong authentication provider")
        else
          user_flow_existing(env, email)
        end
      else
        user_flow_new(env, email, nil, "oidc:" + provider_k)
      end

    rescue ex
      LOGGER.error("OIDC authentication error: #{ex.message}")
      return error_template(500, "Authentication failed: #{ex.message}")
    end

    env.redirect referer
  end

  def self.user_flow_existing(env, email)
    sid = Base64.urlsafe_encode(Random::Secure.random_bytes(32))
    Invidious::Database::SessionIDs.insert(sid, email)
    # Create SID cookie with correct path for all domains
    env.response.cookies["SID"] = HTTP::Cookie.new(
      name: "SID",
      domain: CONFIG.domain == "localhost" ? nil : CONFIG.domain,
      value: sid,
      expires: Time.utc + 2.years,
      secure: CONFIG.https_only || CONFIG.domain != "localhost",
      http_only: true,
      samesite: HTTP::Cookie::SameSite::Lax,
      path: "/"
    )

    if env.request.cookies["PREFS"]?
      cookie = env.request.cookies["PREFS"]
      cookie.expires = Time.utc(1990, 1, 1)
      env.response.cookies << cookie
    end
  end

  def self.user_flow_new(env, email, password, provider)
    sid = Base64.urlsafe_encode(Random::Secure.random_bytes(32))
    if provider.starts_with?("oidc:")
      user, sid = create_oidc_user(sid, email, provider)
    else
      user, sid = create_user(sid, email, password)
    end

    if language_header = env.request.headers["Accept-Language"]?
      if language = ANG.language_negotiator.best(language_header, LOCALES.keys)
        user.preferences.locale = language.header
      end
    end

    Invidious::Database::Users.insert(user)
    Invidious::Database::SessionIDs.insert(sid, email)

    view_name = "subscriptions_#{sha256(user.email)}"
    PG_DB.exec("CREATE MATERIALIZED VIEW #{view_name} AS #{MATERIALIZED_VIEW_SQL.call(user.email)}")

    # Create SID cookie with correct path for all domains
    env.response.cookies["SID"] = HTTP::Cookie.new(
      name: "SID",
      domain: CONFIG.domain == "localhost" ? nil : CONFIG.domain,
      value: sid,
      expires: Time.utc + 2.years,
      secure: CONFIG.https_only || CONFIG.domain != "localhost",
      http_only: true,
      samesite: HTTP::Cookie::SameSite::Lax,
      path: "/"
    )

    if env.request.cookies["PREFS"]?
      user.preferences = env.get("preferences").as(Preferences)
      Invidious::Database::Users.update_preferences(user)
      cookie = env.request.cookies["PREFS"]
      cookie.expires = Time.utc(1990, 1, 1)
      env.response.cookies << cookie
    end
  end
end
