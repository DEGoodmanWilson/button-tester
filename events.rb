require 'sinatra/base'
require 'slack-ruby-client'
require 'mongo'
require 'uri'
require 'json'
require 'securerandom'
require_relative 'helpers'

# Fly me to the moon, let me dance among the stars...
class Events < Sinatra::Base

  # This function contains code common to all endpoints: JSON extraction, setting up some instance variables, and checking verification tokens (for security)
  before do
    body = request.body.read

    # Extract the Event payload from the request and parse the JSON. We can reasonably assume this will be present
    error = false
    begin
      @request_data = JSON.parse(body)
    rescue JSON::ParserError
      error = true
    end

    if error
      # the payload might be URI encoded. Partly. Seriously. We'll need to try again. This happens for message actions webhooks only
      begin
        body = body.split('payload=', 2)[1]
        @request_data = JSON.parse(URI.decode(body))
      rescue JSON::ParserError => e
        halt 419, "Malformed event payload"
      end
    end

    # What team generated this event?
    @team_id = @request_data['team_id']
    # maybe this is a message action, in which case we have to dig deeper. This is one place where the Slack API is maddeningly inconsistent
    @team_id = @request_data['team']['id'] if @team_id.nil? && @request_data['team']

    # Load up the Slack application tokens for this team and put them where we can reach them.
    @token = $tokens.find({team_id: @team_id}).first

    # Check the verification token provided with the request to make sure it matches the verification token in
    # your app's setting to confirm that the request came from Slack.
    unless SLACK_CONFIG[:slack_verification_token] == @request_data['token']
      halt 403, "Invalid Slack verification token received: #{@request_data['token']}"
    end
  end

  # This cool function allows us to write Sinatra endpoints for individual events of interest directly! How fun! Magic!
  set(:event) do |value|
    condition do
      # Each Slack event has a unique `type`. The `message` event also has a `subtype`, sometimes, that we can capture too.
      # Let's make message subtypes look like `message.subtype` for convenience
      return true if @request_data['type'] == value

      if @request_data['type'] == 'event_callback'
        type = @request_data['event']['type']
        unless @request_data['event']['subtype'].nil?
          type = type + '.' + @request_data['event']['subtype']
        end
        return true if type == value
      end

      return false
    end
  end


  ####################################
  # Event handlers
  #

  # See? I said it would be fun. Here is the endpoint for handling the necessary events endpoint url verification, which
  # is a one-time step in the application creation process. We have to do it :( Exactly once. But it's easy.
  post '/events', :event => 'url_verification' do
    return @request_data['challenge']
  end


  # Now things get a bit more exciting. Here is the endpoint for handling user messages! We need to determine whether to
  # index, run a query, or ignore the message, and then possibly render a response.
  post '/events', :event => 'message' do

    message = @request_data['event']

    # First of all, ignore all message originating from us
    return if message['user'] == @token['bot_user_id']


    # at this point, lots of things could happen.
    # This could be an ambient message that we should scan for links to index
    # Or this could be a message directed at _us_, in which case we should treat it as a search query.
    #  Note that we don't want to index either search queries, or anything _we_ post into the channel!


    # The rule we're going to use is this:
    # Index only messages a) not addressed to us and b) in a public channel

    # Now, is this message addressed to us?
    is_addressed_to_us = !Regexp.new('<@'+@token['bot_user_id']+'>').match(message['text']).nil?

    # Is it in a DM?
    is_in_dm = message['channel'][0] == 'D'

    # Is it in a public channel?
    is_in_public_channel = message['channel'][0] == 'C'

    # Does the message satisfy the rule above? Index it!
    if is_in_public_channel && !is_addressed_to_us
      halt 200
    end

    # The other rule is: If the message is meant for us, then show some buttons
    if is_in_dm || is_addressed_to_us
      # Finally, post that reply back in the same channel that the query came from
      msg_id = SecureRandom.hex(12)
      response_msg = {
          channel: message['channel'],
          text: 'Pick a button, any button',
          attachments: [
              {
                  mrkdwn_in: ['text'],
                  text: 'These buttons _do_ things',
                  fallback: 'You are unable to pick a button',
                  callback_id: msg_id,
                  color: '#3AA3E3',
                  attachment_type: 'default',
                  actions: [
                      {
                          name: 'one',
                          text: 'Simple message replace',
                          type: 'button',
                          value: 'one'
                      },
                      {
                          name: 'two',
                          text: 'Remove buttons',
                          type: 'button',
                          value: 'two'
                      },
                      {
                          name: 'three',
                          text: 'Remove butons and async update',
                          type: 'button',
                          value: 'three'
                      }
                  ]
              }
          ]
      }
      $messages.insert_one(response_msg.merge({callback_id: msg_id}))
      client = create_slack_client(@token['bot_access_token'])
      client.chat_postMessage response_msg
    end

    # else, do nothing. Ignore the message.
    status 200
  end


  # Here is the endpoint for handling message actions
  # We end up here if someone clicked a button in one of our messages.
  post '/buttons' do
    # {"actions"=>[{"name"=>"three", "value"=>"three"}], "callback_id"=>"61fda01a906e21a0a85e012a", "team"=>{"id"=>"T0JFD6M53", "domain"=>"slack-hackers"}, "channel"=>{"id"=>"D3EM2LVEU", "name"=>"directmessage"}, "user"=>{"id"=>"U0JFHT99N", "name"=>"don"}, "action_ts"=>"1481828713.719028", "message_ts"=>"1481828634.000019", "attachment_id"=>"1", "token"=>"HSl3wqyz9R24cY8CC6dv6IB1", "original_message"=>{"text"=>"Pick+a+button,+any+button", "username"=>"Button+Tester", "bot_id"=>"B3G2X2SHL", "attachments"=>[{"callback_id"=>"61fda01a906e21a0a85e012a", "fallback"=>"You+are+unable+to+pick+a+button", "text"=>"These+buttons+_do_+things", "id"=>1, "color"=>"3AA3E3", "actions"=>[{"id"=>"1", "name"=>"one", "text"=>"One", "type"=>"button", "value"=>"one", "style"=>""}, {"id"=>"2", "name"=>"two", "text"=>"Two", "type"=>"button", "value"=>"two", "style"=>""}, {"id"=>"3", "name"=>"three", "text"=>"Three", "type"=>"button", "value"=>"three", "style"=>""}]}], "type"=>"message", "subtype"=>"bot_message", "ts"=>"1481828634.000019"}, "response_url"=>"https://hooks.slack.com/actions/T0JFD6M53/116724109376/ebzOxk2uhI5pfU5wWhrksHqY"}


    # fetch the message from the DB
    msg = $messages.find({callback_id: @request_data['callback_id']}).first


    case @request_data['actions'][0]['name']
      when 'one'
        msg['text'] = 'BOOYA ONE!'
      when 'two'
        msg['text'] = 'BOOYA TWO!'
        msg.delete('attachments')
      when 'three'
        msg['text'] = 'BOOYA THREE!'
        msg.delete('attachments')
    end

    # Update the DB
    $messages.update_one({callback_id: @request_data['callback_id']}, msg)


    if @request_data['actions'][0]['name'] == 'three'
      t = Thread.new(@token, @request_data, msg){ |token, request_data, nmsg|
        sleep 0.1
        nmsg['text'] = 'BOOYA DONE!'
        $messages.update_one({callback_id: nmsg['callback_id']}, nmsg)
        client = create_slack_client(token['bot_access_token'])
        client.chat_update(text: 'BOOYA DONE!', ts: request_data['message_ts'], channel: nmsg['channel'])
      }
    end

    # Rather than posting a new message, we'll just respond with the new message to replace the old message!
    content_type :json
    msg.to_json
  end
end