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

require 'bbb_api'
require 'uri'

module ApplicationHelper
  # Determines which providers can show a login button in the login modal.
  def iconset_providers
    providers = configured_providers & [:google, :twitter, :office365, :ldap]

    providers.delete(:twitter) if session[:old_twitter_user_id]

    providers
  end

  def gluu_login_url
    "#{Rails.configuration.relative_url_root}/gluu_signin"
  end

  # Generates the login URL for a specific provider.
  def omniauth_login_url(provider)
    if provider == :ldap
      ldap_signin_path
    else
      "#{Rails.configuration.relative_url_root}/auth/#{provider}"
    end
  end

  # Determines if a form field needs the is-invalid class.
  def form_is_invalid?(obj, key)
    'is-invalid' unless obj.errors.messages[key].empty?
  end

  # Return all the translations available in the client side through javascript
  def current_translations
    @translations ||= I18n.backend.send(:translations)
    @translations[I18n.locale]
  end

  # Return the fallback translations available in the client side through javascript
  def fallback_translations
    @fallback_translations ||= I18n.backend.send(:translations)
    @fallback_translations[I18n.default_locale]
  end

  # Returns the page that the logo redirects to when clicked on
  def home_page
    return root_path unless current_user
    return admins_path if current_user.has_role? :super_admin
    current_user.main_room
  end

  # Returns the action method of the current page
  def active_page
    route = Rails.application.routes.recognize_path(request.env['PATH_INFO'])

    route[:action]
  end

  def role_colour(role)
    role.colour || Rails.configuration.primary_color_default
  end

  def translated_role_name(role)
    if role.name == "denied"
      I18n.t("roles.banned")
    elsif role.name == "pending"
      I18n.t("roles.pending")
    elsif role.name == "admin"
      I18n.t("roles.admin")
    elsif role.name == "user"
      I18n.t("roles.user")
    else
      role.name
    end
  end

  def can_reset_password
    # Check if admin is editting user and user is a greenlight account
    Rails.configuration.enable_email_verification &&
        Rails.application.routes.recognize_path(request.env['PATH_INFO'])[:action] == "edit_user" &&
        @user.greenlight_account?
  end

  def google_analytics_url
    "https://www.googletagmanager.com/gtag/js?id=#{ENV['GOOGLE_ANALYTICS_TRACKING_ID']}"
  end

  def valid_url?(input)
    uri = URI.parse(input)
    !uri.host.nil?
  rescue URI::InvalidURIError
    false
  end
    # Specifies which title should be the tab title and returns original string
    def title(page_title)
      # Only set the content_for if not already set on the page so that only the first title appears as the tab title
      content_for(:page_title) { page_title } if content_for(:page_title).blank?
      page_title
    end
  
    # Indicates whether the recording tables should be hidden
    def hide_recording_tables
      return false unless recording_consent_required?
      @settings.get_value("Room Configuration Recording") == "disabled"
    end
  
    # Hide the signin buttons if there is an error on the page
    def show_signin
      !@hide_signin.present?
    end
  
    # Returns a more friendly/readable date time object
    def view_date(date)
      return "" if date.nil? # Handle invalid dates
      local_time(date, "%b %d, %Y %-I:%M%P")
    end
end
