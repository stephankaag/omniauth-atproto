require 'omniauth-oauth2'
require 'json'
require 'net/http'
require 'atproto_client'

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      def initialize(app, *args)
        super
        @dpop_handler = AtProto::DpopHandler.new(options.private_key)
      end

      option :scope, 'atproto'
      option :pkce, true
      option :token_params, {
        test: true
      }

      info do
        {
          did: @access_token.params['sub'],
          pds_host: options.client_options.site
        }
      end

      private

      def build_access_token
        new_token_params = token_params.merge(
          {
            grant_type: 'authorization_code',
            redirect_uri: full_host + callback_path,
            code: request.params['code'],
            client_id: options.client_id,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: generate_client_assertion
          }
        )
        response = @dpop_handler.make_request(
          client.token_url,
          :post,
          headers: { 'Content-Type' => 'application/json', 'Accept' => 'application/json' },
          body: new_token_params
        )

        ::OAuth2::AccessToken.from_hash(client, response)
      end

      def generate_client_assertion
        # Should return a JWT signed with the private key corresponding to the one in client-metadata.json

        raise 'Client ID is required' unless options.client_id
        raise 'Client JWK is required' unless options.client_jwk

        private_key = if options.private_key.is_a?(String)
                        OpenSSL::PKey::EC.new(options.private_key)
                      elsif options.private_key.is_a?(OpenSSL::PKey::EC)
                        options.private_key
                      else
                        raise 'Invalid private_key format'
                      end

        jwt_payload = {
          iss: options.client_id,
          sub: options.client_id,
          aud: options.client_options.site,
          jti: SecureRandom.uuid,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 300
        }

        JWT.encode(
          jwt_payload,
          private_key,
          'ES256',
          {
            typ: 'jwt',
            alg: 'ES256',
            kid: options.client_jwk[:kid]
          }
        )
      end
    end
  end
end
