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
    result = grantedbyme.get_session_token
  elsif params[:operation] == 'getSessionState'
    result = grantedbyme.get_token_state(params[:token])
    if result['success'] and result['status'] == 3
      grantor = result['grantor']
      user_id = redis.get 'user_id_by_grantor_' + grantor
      if user_id
        session[:logged_in] = true
        session[:user_id] = user_id
        flash_log 'Logged in user: ' + user_id
      end
      result.delete('grantor')
    end
  elsif params[:operation] == 'getAccountToken'
    result = grantedbyme.get_account_token
  elsif params[:operation] == 'getAccountState'
    result = grantedbyme.get_token_state(params[:token])
    if result['success'] and result['status'] == 3
      grantor = grantedbyme.get_random_string(128)
      link_result = grantedbyme.link_account(params[:token], grantor)
      if link_result['success']
        user_id = session[:user_id]
        user_data = JSON.parse(redis.get('user_by_id_' + user_id))
        user_data['grantor'] = grantor
        redis.set 'user_by_id_' + user_id, user_data.to_json
        redis.set 'user_id_by_grantor_' + grantor, user_id
        flash_log 'User account updated: ' + user_id
      end
    end
  elsif params[:operation] == 'getRegisterToken'
    result = grantedbyme.get_register_token
  elsif params[:operation] == 'getRegisterState'
    result = grantedbyme.get_token_state(params[:token])
    if result['success'] and result['status'] == 3
      logger.info result['data']
      grantor = grantedbyme.get_random_string(128)
      link_result = grantedbyme.link_account(params[:token], grantor)
      if link_result['success']
        redis.incr 'user_counter'
        user_id = redis.get 'user_counter'
        email = result['data']['email']
        first_name = result['data']['first_name']
        last_name = result['data']['last_name']
        user_data = {'grantor': grantor, 'email': email, 'first_name': first_name, 'last_name': last_name, 'user_id': user_id}
        redis.set 'user_by_id_' + user_id, user_data.to_json
        redis.set 'user_id_by_grantor_' + grantor, user_id
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
  cipher_request = {}
  cipher_request['signature'] = params[:signature]
  cipher_request['payload'] = params[:payload]
  cipher_request['message'] = params[:message]
  plain_request = grantedbyme.get_crypto.decrypt(params, grantedbyme.get_private_key, grantedbyme.get_server_key)
  logger.info "callback: #{plain_request}"
  plain_result = {}
  plain_result['success'] = false
  # logger.info "plain_result: #{plain_result}"
  encrypted_result = grantedbyme.get_crypto.encrypt(plain_result, grantedbyme.get_private_key, grantedbyme.get_server_key)
  # logger.info "encrypted_result: #{encrypted_result}"
  return encrypted_result
end
