require 'omniauth-oauth2'
require 'json'
require 'net/http'
require 'atproto_client'
require 'didkit'
require 'faraday'

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      option :fields, %i[handle]
      option :scope, 'atproto'
      option :pkce, true

      info do
        {
          did: @access_token.params['sub'],
          pds_host: options.client_options.site
        }
      end

      def request_phase
        unless has_default_client_options?
          @handle = request.params['handle']

          unless @handle
            fail!(:missing_handle,
                  OmniAuth::Error.new(
                    'Handle parameter is required if no client options are set'
                  ))
          end

          set_client_options
        end
        super
      end

      private

      def has_default_client_options?
        %i[site authorize_url token_url].all? { |k| options.client_options.key? k }
      end

      def set_client_options
        options.client_options[:site] = authorization_info['issuer']
        options.client_options[:authorize_url] = authorization_info['authorization_endpoint']
        options.client_options[:token_url] = authorization_info['token_endpoint']
      end

      def authorization_info
        session['omniauth.auth_info'] ||= begin
          resolver = DIDKit::Resolver.new
          did = resolver.resolve_handle(@handle)
          endpoint = resolver.resolve_did(did).pds_endpoint
          auth_server = get_authorization_server(endpoint)
          auth_info = get_authorization_data(auth_server)
        end
      end

      def build_access_token
        set_client_options unless has_default_client_options?

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
        dpop_handler = AtProto::DpopHandler.new(options.private_key)
        response = dpop_handler.make_request(
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

      def get_authorization_server(pds_endpoint)
        response = Faraday.get("#{pds_endpoint}/.well-known/oauth-protected-resource")

        unless response.success?
          fail!(:invalid_auth_server,
                OmniAuth::Error.new(
                  "Failed to get PDS authorization server: #{response.status}"
                ))
        end

        result = JSON.parse(response.body)

        auth_server = result.dig('authorization_servers', 0)
        unless auth_server
          fail!(:invalid_auth_server,
                OmniAuth::Error.new('No authorization server found in response'))
        end
        auth_server
      end

      def get_authorization_data(issuer)
        response = Faraday.get("#{issuer}/.well-known/oauth-authorization-server")

        unless response.success?
          fail!(:invalid_metadata,
                OmniAuth::Error.new(
                  "Failed to get authorization server metadata: #{response.status}"
                ))
        end
        result = JSON.parse(response.body)

        unless result['issuer'] == issuer
          fail!(:invalid_metadata,
                OmniAuth::Error.new('Invalid metadata - issuer mismatch'))
        end
        # we cannot keep everything in session (cookie overflow error)
        fields = %w[issuer authorization_endpoint token_endpoint]
        result.select { |k, _v| fields.include?(k) }
      end
    end
  end
end
