

# Omniauth-atproto

An omniauth strategy for Atproto (bluesky)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-atproto'
```


## Usage

You can cnfigure it :
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider(:atproto,
    "#{Rails.application.config.app_url}/oauth/client-metadata.json",
    nil,
    client_options: {
        site: "https://bsky.social",
        authorize_url: "https://bsky.social/oauth/authorize",
        token_url: "https://bsky.social/oauth/token"
    },
    scope: "atproto transition:generic",
    private_key: OmniAuth::Atproto::KeyManager.current_private_key,
    client_jwk: OmniAuth::Atproto::KeyManager.current_jwk)
end
```
You will have to generate keys and the oauth/client-metadata.json document (a generator should come soon)

```ruby
#lib/tasks/atproto.rake
:atproto do
  desc "Generate new AtProto key pair and rotate keys"
  task rotate_keys: :environment do
    OmniAuth::Atproto::KeyManager.rotate_keys
    puts "New key generated and saved. Old key backed up if it existed."
    Rake::Task["atproto:generate_metadata"].invoke
  end

  desc "Generate client metadata JSON file"
  task generate_metadata: :environment do
    metadata = {
      client_id: "#{Rails.application.config.app_url}/oauth/client-metadata.json",
      application_type: "web",
      client_name: Rails.application.class.module_parent_name,
      client_uri: Rails.application.config.app_url,
      dpop_bound_access_tokens: true,
      grant_types: %w[authorization_code refresh_token],
      redirect_uris: [ "#{Rails.application.config.app_url}/auth/atproto/callback" ],
      response_types: [ "code" ],
      scope: "atproto transition:generic",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: {
        keys: [ OmniAuth::Atproto::KeyManager.current_jwk ]
      }
    }

    oauth_dir = Rails.root.join("public", "oauth")
    FileUtils.mkdir_p(oauth_dir) unless Dir.exist?(oauth_dir)
    metadata_path = oauth_dir.join("client-metadata.json")
    File.write(metadata_path, JSON.pretty_generate(metadata))
    puts "Generated metadata file at #{metadata_path}"
  end
end
```
Then you can
```bash
rails atproto:generate_metadata
```
The values from the metadata endpoint should correspond to those you gave as option for the strategy (that's why a generator would be very handy) 
