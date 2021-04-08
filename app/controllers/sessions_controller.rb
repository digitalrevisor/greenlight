# frozen_string_literal: true

# BigBlueButton open source conferencing system - http://www.bigbluebutton.org/.
#
# Copyright (c) 2018 BigBlueButton Inc. and by respective authors (see below).
#
# This program is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free Software
# Foundation; either version 3.0 of the License, or (at your option) any later
# version.
#
# BigBlueButton is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with BigBlueButton; if not, see <http://www.gnu.org/licenses/>.

class SessionsController < ApplicationController
  include Authenticator
  include Registrar
  include Emailer
  include LdapAuthenticator

  skip_before_action :verify_authenticity_token, only: [:omniauth, :fail]
  before_action :check_user_signup_allowed, only: [:new]
  before_action :ensure_unauthenticated_except_twitter, only: [:new, :signin]


  #----------------GLUU--------------
  # GET /gluu_signin
  def gluu_signin
    client = get_oidc_client
    session[:state] = SecureRandom.hex(16)
    session[:nonce] = SecureRandom.hex(16)

    authorization_uri = client.authorization_uri(
        scope: [:profile, :email, 'drRoles', 'subscriptions'],
        state: session[:state],
        nonce: session[:nonce]
    )
    redirect_to authorization_uri
  end

  # GET /gluu_callback
  def gluu_callback
    client = get_oidc_client

    # Authorization Response
    vars = request.query_parameters
    code = vars['code']
    state = vars['state']

    if session[:state] != state
      redirect_to root_path, alert: I18n.t("gluu_error")
      return
    end

    # Token Request
    client.authorization_code = code
    access_token = client.access_token!
    id_token = jwt = JSON::JWT.decode  access_token.id_token, :skip_verification
    session[:id_token]=access_token.id_token
    # id_token = OpenIDConnect::ResponseObject::IdToken.decode access_token.id_token, nil # => OpenIDConnect::ResponseObject::IdToken
    userinfo = access_token.userinfo!

    roles=""

    if (! userinfo.raw_attributes.key?("subscriptions")) || ( ! userinfo.raw_attributes["subscriptions"].include? Rails.application.config.gluu_user_role)
      redirect_to Rails.application.config.gluu_invalid_subscription_url
      return
    else
      if userinfo.raw_attributes["subscriptions"].include? Rails.application.config.gluu_user_role
        roles="user"
      end
      if userinfo.raw_attributes["subscriptions"].include? Rails.application.config.gluu_admin_role
        roles="user,admin"
      end
    end

    if session[:nonce] != id_token.as_json['nonce']
      redirect_to root_path, alert: I18n.t("gluu_error")
      return
    end

    info = {
        "email" => userinfo.email,
        "nickname" => userinfo.email,
        "name" => userinfo.given_name,
        "roles" => roles
    }

    @auth = {"info"=> info, "uid"=> userinfo.email,"provider"=>"DigitalRevisor"}

    begin
      process_signin
    rescue => e
      logger.error "Error authenticating via Gluu: #{e}"
      omniauth_fail
    end
  end

  def get_oidc_client
    response = get_idp_config
    client = OpenIDConnect::Client.new(
        identifier: Rails.application.config.gluu_client_id,
        secret: Rails.application.config.gluu_secret,
        redirect_uri: request.base_url + Rails.application.config.gluu_app_context+ '/gluu_callback',
        host: Rails.application.config.gluu_host,
        authorization_endpoint: response.authorization_endpoint,
        token_endpoint: response.token_endpoint,
        userinfo_endpoint: response.userinfo_endpoint
    )
  end

  def get_idp_config
    response = OpenIDConnect::Discovery::Provider::Config.discover! Rails.application.config.gluu_host
  end

  # GET /users/logout
  def destroy
    logout
    config = get_idp_config
    path = config.end_session_endpoint
    redirect_to path + "?post_logout_redirect_uri="+root_url+"&id_token_hint="+session[:id_token].to_s
  end


  #-----------------------------------------------------------
  # GET /signin
  def signin
    check_if_twitter_account

    if one_provider
      provider_path = if Rails.configuration.omniauth_ldap
                        ldap_signin_path
                      else
                        "#{Rails.configuration.relative_url_root}/auth/#{providers.first}"
                      end

      return redirect_to provider_path
    end
  end

  # GET /ldap_signin
  def ldap_signin
  end

  # GET /signup
  def new
    # Check if the user needs to be invited
    if invite_registration
      redirect_to root_path, flash: { alert: I18n.t("registration.invite.no_invite") } unless params[:invite_token]

      session[:invite_token] = params[:invite_token]
    end

    check_if_twitter_account(true)

    @user = User.new
  end

  # POST /users/login
  def create
    logger.info "Support: #{session_params[:email]} is attempting to login."

    user = User.include_deleted.find_by(email: session_params[:email], provider: @user_domain)

    # Check user with that email exists
    return redirect_to(signin_path, alert: I18n.t("invalid_credentials")) unless user
    # Check correct password was entered
    return redirect_to(signin_path, alert: I18n.t("invalid_credentials")) unless user.try(:authenticate,
                                                                                          session_params[:password])
    # Check that the user is not deleted
    return redirect_to root_path, flash: { alert: I18n.t("registration.banned.fail") } if user.deleted?

    unless user.has_role? :super_admin
      # Check that the user is a Greenlight account
      return redirect_to(root_path, alert: I18n.t("invalid_login_method")) unless user.greenlight_account?
      # Check that the user has verified their account
      return redirect_to(account_activation_path(email: user.email)) unless user.activated?
    end

    login(user)
  end

  # # GET /users/logout
  # def destroy
  #   logout
  #   redirect_to root_path
  # end

  # GET/POST /auth/:provider/callback
  def omniauth
    @auth = request.env['omniauth.auth']

    begin
      process_signin
    rescue => e
      logger.error "Error authenticating via omniauth: #{e}"
      omniauth_fail
    end
  end

  # POST /auth/failure
  def omniauth_fail
    if params[:message].nil?
      redirect_to root_path, alert: I18n.t("omniauth_error")
    else
      redirect_to root_path, alert: I18n.t("omniauth_specific_error", error: params["message"])
    end
  end

  # GET /auth/ldap
  def ldap
    ldap_config = {}
    ldap_config[:host] = ENV['LDAP_SERVER']
    ldap_config[:port] = ENV['LDAP_PORT'].to_i != 0 ? ENV['LDAP_PORT'].to_i : 389
    ldap_config[:bind_dn] = ENV['LDAP_BIND_DN']
    ldap_config[:password] = ENV['LDAP_PASSWORD']
    ldap_config[:encryption] = if ENV['LDAP_METHOD'] == 'ssl'
                                 'simple_tls'
                               elsif ENV['LDAP_METHOD'] == 'tls'
                                 'start_tls'
                               end
    ldap_config[:base] = ENV['LDAP_BASE']
    ldap_config[:uid] = ENV['LDAP_UID']

    result = send_ldap_request(params[:session], ldap_config)

    return redirect_to(ldap_signin_path, alert: I18n.t("invalid_credentials")) unless result

    @auth = parse_auth(result.first, ENV['LDAP_ROLE_FIELD'])

    begin
      process_signin
    rescue => e
      logger.error "Support: Error authenticating via omniauth: #{e}"
      omniauth_fail
    end
  end

  private

  # Verify that GreenLight is configured to allow user signup.
  def check_user_signup_allowed
    redirect_to root_path unless Rails.configuration.allow_user_signup
  end

  def session_params
    params.require(:session).permit(:email, :password)
  end

  def one_provider
    providers = configured_providers

    (!allow_user_signup? || !allow_greenlight_accounts?) && providers.count == 1 &&
        !Rails.configuration.loadbalanced_configuration
  end

  def check_user_exists
    User.exists?(social_uid: @auth['uid'], provider: current_provider)
  end

  def check_user_deleted(email)
    User.deleted.exists?(email: email, provider: @user_domain)
  end

  def check_auth_deleted
    User.deleted.exists?(social_uid: @auth['uid'], provider: current_provider)
  end

  def current_provider
    @auth['provider'] == "bn_launcher" ? @auth['info']['customer'] : @auth['provider']
  end

  # Check if the user already exists, if not then check for invitation
  def passes_invite_reqs
    return true if @user_exists

    invitation = check_user_invited("", session[:invite_token], @user_domain)
    invitation[:present]
  end

  def process_signin
    @user_exists = check_user_exists

    if !@user_exists && @auth['provider'] == "twitter"
      return redirect_to root_path, flash: { alert: I18n.t("registration.deprecated.twitter_signup") }
    end

    # Check if user is deleted
    return redirect_to root_path, flash: { alert: I18n.t("registration.banned.fail") } if check_auth_deleted

    # If using invitation registration method, make sure user is invited
    return redirect_to root_path, flash: { alert: I18n.t("registration.invite.no_invite") } unless passes_invite_reqs

    user = User.from_omniauth(@auth)

    logger.info "Support: Auth user #{user.email} is attempting to login."

    # Add pending role if approval method and is a new user
    if approval_registration && !@user_exists
      user.add_role :pending

      # Inform admins that a user signed up if emails are turned on
      send_approval_user_signup_email(user)

      return redirect_to root_path, flash: { success: I18n.t("registration.approval.signup") }
    end

    send_invite_user_signup_email(user) if invite_registration && !@user_exists

    login(user)

    if @auth['provider'] == "twitter"
      flash[:alert] = if allow_user_signup? && allow_greenlight_accounts?
                        I18n.t("registration.deprecated.twitter_signin", link: signup_path(old_twitter_user_id: user.id))
                      else
                        I18n.t("registration.deprecated.twitter_signin", link: signin_path(old_twitter_user_id: user.id))
                      end
    end
  end
end