##
# GrantedByMe Ruby SDK Sinatra integration example
# author: GrantedByMe <info@grantedby.me>
#

require 'sinatra'
require 'rack-flash'
require 'redis'
require 'json'
require 'tilt/erb'

$LOAD_PATH.unshift(File.dirname(__FILE__) + '/../../lib')
$LOAD_PATH.unshift(File.dirname(__FILE__) + '/lib')
require 'grantedbyme'

# https://github.com/sinatra/sinatra
# http://www.sinatrarb.com/configuration.html
set :port, 5006
enable :sessions, :logging
set :session_secret, 'gF4d7fJgD4grzU5c2gGUnC3s'

# https://github.com/treeder/rack-flash
use Rack::Flash

configure :development do
  # http://www.sinatrarb.com/contrib/reloader.html
  # require 'sinatra/reloader'
  # enable :reloader
  # register Sinatra::Reloader
  file = File.new("#{__dir__}/logs/app.log", 'a+')
  file.sync = true
  use Rack::CommonLogger, file
end

# GrantedByMe API key data folder
base_dir = File.dirname(__FILE__) + '/../../data/'
puts 'Base dir: ' + base_dir
grantedbyme = GrantedByMe.new(private_key_file: base_dir + 'private_key.pem', server_key_file: base_dir + 'server_key.pem')

# Initialize Redis DB
# https://github.com/redis/redis-rb
redis_db = 4
redis = Redis.new(:host => 'localhost', :port => 6379, :db => redis_db)

# User counter default
counter = redis.get('user_counter')
if not counter
  redis.set('user_counter', 0)
end

# Helpers

def flash_log(message)
  logger.info message
  flash[:notice] = message
end

########################################
# Routes
########################################

get '/' do
  if not session[:logged_in]
    redirect to('/login')
  end
  erb :index
end

get '/login' do
  if session[:logged_in]
    redirect to('/')
  end
  erb :login
end

get '/logout' do
  session[:logged_in] = false
  session[:user_id] = 0
  flash_log 'Logged out'
  redirect to('/login')
end

get '/register' do
  if session[:logged_in]
    redirect to('/')
  end
  erb :register
end

get '/account' do
  if not session[:logged_in]
    redirect to('/login')
  end
  erb :account
end

get '/flushdb' do
  flash_log 'Flushed database'
  redis.flushdb()
  redirect to('/logout')
end

get '/ping' do
  result = {'success': true}
  result.to_json
end

########################################
# GBM HTML5 Ajax
########################################

post '/ajax' do
  result = '{"success": false}'
  if env['HTTP_X_REQUESTED_WITH'] != 'XMLHttpRequest' and env['X-Requested-With'] != 'XMLHttpRequest'
    logger.info 'Request error'
    return result
  end
  # logger.info "operation: #{operation}"
  if params[:operation] == 'getSessionToken'
    result = grantedbyme.get_challenge(GrantedByMe.challenge_authenticate)
  elsif params[:operation] == 'getSessionState'
    result = grantedbyme.get_challenge_state(params[:challenge])
    if result['success'] and result['status'] == 3
      authenticator_secret = result['authenticator_secret']
      user_id = redis.get 'user_id_by_authenticator_secret_' + authenticator_secret
      if user_id
        session[:logged_in] = true
        session[:user_id] = user_id
        flash_log 'Logged in user: ' + user_id
      end
      result.delete('authenticator_secret')
    end
  elsif params[:operation] == 'getAccountToken'
    result = grantedbyme.get_challenge(GrantedByMe.challenge_authorize)
  elsif params[:operation] == 'getAccountState'
    result = grantedbyme.get_challenge_state(params[:challenge])
    if result['success'] and result['status'] == 3
      authenticator_secret = GrantedByMe.generate_authenticator_secret
      link_result = grantedbyme.link_account(params[:challenge], authenticator_secret)
      if link_result['success']
        user_id = session[:user_id]
        user_data = JSON.parse(redis.get('user_by_id_' + user_id))
        user_data['authenticator_secret'] = authenticator_secret
        redis.set 'user_by_id_' + user_id, user_data.to_json
        redis.set 'user_id_by_authenticator_secret_' + authenticator_secret, user_id
        flash_log 'User account updated: ' + user_id
      end
    end
  elsif params[:operation] == 'getRegisterToken'
    result = grantedbyme.get_challenge(GrantedByMe.challenge_profile)
  elsif params[:operation] == 'getRegisterState'
    result = grantedbyme.get_challenge_state(params[:challenge])
    if result['success'] and result['status'] == 3
      logger.info result['data']
      authenticator_secret = GrantedByMe.generate_authenticator_secret
      link_result = grantedbyme.link_account(params[:challenge], authenticator_secret)
      if link_result['success']
        redis.incr 'user_counter'
        user_id = redis.get 'user_counter'
        email = result['data']['email']
        first_name = result['data']['first_name']
        last_name = result['data']['last_name']
        user_data = {'authenticator_secret': authenticator_secret, 'email': email, 'first_name': first_name, 'last_name': last_name, 'user_id': user_id}
        redis.set 'user_by_id_' + user_id, user_data.to_json
        redis.set 'user_id_by_authenticator_secret_' + authenticator_secret, user_id
        redis.set 'user_id_by_email_' + email, user_id
        flash_log 'User account created: ' + user_id
      end
      result.delete('data')
    end
  end
  # logger.info "result: #{result}"
  if result.class == Hash
    return result.to_json
  end
  return result
end

########################################
# GBM Server Callback
########################################

post '/callback' do
  result = {'success': false}
  if params.has_key?('signature') and params.has_key?('payload')
    cipher_request = {}
    cipher_request['signature'] = params[:signature]
    cipher_request['payload'] = params[:payload]
    if params.has_key?('message')
      cipher_request['message'] = params[:message]
    end
    plain_request = grantedbyme.get_crypto.decrypt(cipher_request)
    logger.info "callback: #{plain_request}"
    plain_result = {}
    plain_result['success'] = false
    if plain_request.has_key?('operation')
      if plain_request['operation'] == 'ping'
        plain_result['success'] = true
      elsif plain_request['operation'] == 'unlink_account'
        if plain_request.has_key?('authenticator_secret_hash')
            # TODO: implement
        end
      elsif plain_request['operation'] == 'rekey_account'
        if plain_request.has_key?('authenticator_secret_hash')
            # TODO: implement
        end
      elsif plain_request['operation'] == 'revoke_challenge'        
        if plain_request.has_key?('challenge')
            # TODO: implement
        end
      else
        logger.info "callback operation not handled: #{plain_request['operation']}"
      end
    end
    # logger.info "plain_result: #{plain_result}"
    result = grantedbyme.get_crypto.encrypt(plain_result)
    # logger.info "result: #{result}"
  end
  if result.class == Hash
    return result.to_json
  end
  result
end

