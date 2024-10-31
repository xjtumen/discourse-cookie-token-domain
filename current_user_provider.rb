class ExCurrentUserProvider < Auth::DefaultCurrentUserProvider
  TOKEN_COOKIX ||= "logged_in".freeze

  def log_on_user(user, session, cookies, opts = {})
    super

    require 'openssl' if !defined?(OpenSSL)
    require 'base64' if !defined?(Base64)

    payload = {  id: user.id, username: user.username, name: user.name,
     admin:user.admin, moderator:user.moderator, trust_level: user.trust_level,
     avatar_template: user.avatar_template, title: user.title,
     groups: user.groups, locale: user.locale,
     silenced_till: user.silenced_till , staged: user.staged, active: user.active}
    payload_sha = Digest::SHA256.hexdigest payload.to_json
    hash_function = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(hash_function, SiteSetting.cookie_ui_key, payload_sha)
    payload[:hmac] = hmac
    token = Base64.strict_encode64(payload.to_json)
    cookies.permanent[TOKEN_COOKIX] = { value: token, httponly: true, domain: :all }

  end
  
  def log_off_user(session, cookies)
    super

    cookies[TOKEN_COOKIX] = { value: '', httponly: true, domain: :all }
  end

end
