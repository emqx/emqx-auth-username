%% Copyright (c) 2018 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(emqx_auth_username_SUITE).

-compile(export_all).

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/emqx_mqtt.hrl").

-include_lib("common_test/include/ct.hrl").

-define(TAB, emqx_auth_username).
-record(?TAB, {username, password}).

all() ->
    [{group, emqx_auth_username}].

groups() ->
    [{emqx_auth_username, [sequence],
      [emqx_auth_username_api, 
       t_enhanced_auth,
       t_test_auth,
       t_auth_protocol,
       change_config,
       cli]}].

init_per_suite(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    [start_apps(App, DataDir) || App <- [emqx, emqx_auth_username]],
    Config.

end_per_suite(_Config) ->
    application:stop(emqx_auth_username),
    application:stop(emqx).

emqx_auth_username_api(_Config) ->
    ok = emqx_auth_username:add_user(<<"test_username">>, <<"password">>),
    User1 = #{username => <<"test_username">>},
    User2 = #{username => undefined, auth_method => <<"PLAIN">>, 
              auth_data => <<0,                                                             % U+0000
                             116,101,115,116,95,117,115,101,114,110,97,109,101,             % <<"test_username">>
                             0,                                                             % U+0000
                             112,97,115,115,119,111,114,100>>},                             % <<"password">>
    [{?TAB, <<"test_username">>, _HashedPass}] =
        emqx_auth_username:lookup_user(<<"test_username">>),
    ok = emqx_access_control:authenticate(User1, <<"password">>),
    {ok, _} = emqx_access_control:authenticate(User2, undefined),
    {ok, _} = emqx_access_control:authenticate(User2#{username  := <<"test_username">>,
                                                      auth_data := <<0,                                 % U+0000
                                                                    117,115,101,114,110,97,109,101,     % <<"username">>
                                                                    0,                                  % U+0000
                                                                    112,97,115,115,119,111,114,100>>}, undefined),
    {error, bad_authentication_method} = emqx_access_control:authenticate(User2#{auth_method  := <<"SCRAM-SHA-1">>}, undefined),
    {error, invalid_auth_data} = emqx_access_control:authenticate(#{auth_method => <<"PLAIN">>, auth_data => <<>>}, undefined),
    {error, invalid_auth_data} = emqx_access_control:authenticate(#{auth_method => <<"PLAIN">>}, undefined),
    ok = emqx_auth_username:remove_user(<<"test_username">>),
    {error, _} = emqx_access_control:authenticate(User1, <<"password">>),
    {error, _} = emqx_access_control:authenticate(User2, <<"password">>).

t_enhanced_auth(_Config) ->
    ok = emqx_auth_username:add_user(<<"admin">>, <<"public">>),
    % authenticate with unsupported method. will failed
    {ok, Sock} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"SCRAM-SHA-1">>,
                                                        'Authentication-Data'   => <<0,97,100,109,105,110,          % admin
                                                                                     0,112,117,98,108,105,99>>}})), % public
    emqx_client_sock:send(Sock, Packet),
    {ok, Data} = gen_tcp:recv(Sock, 0),
    {ok, ?CONNACK_PACKET(?RC_BAD_AUTHENTICATION_METHOD), _} = raw_recv_pase(Data),
    emqx_client_sock:close(Sock),

    % authenticate with empty method. will failed
    {ok, Sock1} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet1 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<>>,
                                                        'Authentication-Data'   => <<>>}})),
    emqx_client_sock:send(Sock1, Packet1),
    {ok, Data1} = gen_tcp:recv(Sock1, 0),
    {ok, ?CONNACK_PACKET(?RC_MALFORMED_PACKET), _} = raw_recv_pase(Data1),
    emqx_client_sock:close(Sock1),

    % authenticate with empty data. will failed
    {ok, Sock2} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet2 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"PLAIN">>,
                                                        'Authentication-Data'   => <<>>}})),
    emqx_client_sock:send(Sock2, Packet2),
    {ok, Data2} = gen_tcp:recv(Sock2, 0),
    {ok, ?CONNACK_PACKET(?RC_NOT_AUTHORIZED), _} = raw_recv_pase(Data2),
    emqx_client_sock:close(Sock2),

    % authenticate with bad password. will failed
    {ok, Sock3} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet3 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"PLAIN">>,
                                                        'Authentication-Data'   => <<0,97,100,109,105,110,              % admin
                                                                                     0,112,117,98,108,105,100>>}})),    % publid
    emqx_client_sock:send(Sock3, Packet3),
    {ok, Data3} = gen_tcp:recv(Sock3, 0),
    {ok, ?CONNACK_PACKET(?RC_NOT_AUTHORIZED), _} = raw_recv_pase(Data3),
    emqx_client_sock:close(Sock3),

    % will succeed
    {ok, Sock4} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet4 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"PLAIN">>,
                                                        'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                     0,112,117,98,108,105,99>>}})),
    emqx_client_sock:send(Sock4, Packet4),
    {ok, Data4} = gen_tcp:recv(Sock4, 0),
    {ok, ?CONNACK_PACKET(?RC_SUCCESS), _} = raw_recv_pase(Data4),

    % reauthenticate, will succeed
    Packet5 = raw_send_serialise(?AUTH_PACKET(?RC_RE_AUTHENTICATE, #{'Authentication-Method' => <<"PLAIN">>,
                                                                        'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                                     0,112,117,98,108,105,99>>})),
    emqx_client_sock:send(Sock4, Packet5),
    {ok, Data5} = gen_tcp:recv(Sock4, 0),
    {ok, ?AUTH_PACKET(?RC_SUCCESS), _} = raw_recv_pase(Data5),

    % reauthenticate with bad password, will failed
    Packet6 = raw_send_serialise(?AUTH_PACKET(?RC_RE_AUTHENTICATE, #{'Authentication-Method' => <<"PLAIN">>,
                                                                        'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                                     0,112,117,98,108,105,100>>})),
    emqx_client_sock:send(Sock4, Packet6),
    {ok, Data6} = gen_tcp:recv(Sock4, 0),
    {ok, ?DISCONNECT_PACKET(?RC_NOT_AUTHORIZED), _} = raw_recv_pase(Data6),
    emqx_client_sock:close(Sock4),
    ok = emqx_auth_username:remove_user(<<"admin">>).

t_test_auth(_Config) ->
    ok = emqx_auth_username:add_user(<<"admin">>, <<"public">>),
    % will return auth with continue
    {ok, Sock} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                        'Authentication-Data'   => <<"continue">>}})),
    emqx_client_sock:send(Sock, Packet),
    {ok, Data} = gen_tcp:recv(Sock, 0),
    {ok, ?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' := <<"TEST-AUTH">>,
                                                   'Authentication-Data'   := <<"this is a test auth">>}), _} = raw_recv_pase(Data),

    % will return auth with continue
    Packet1 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                                              'Authentication-Data'   => <<"continue">>})),
    emqx_client_sock:send(Sock, Packet1),
    {ok, Data1} = gen_tcp:recv(Sock, 0),
    {ok, ?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' := <<"TEST-AUTH">>,
                                                   'Authentication-Data'   := <<"this is a test auth">>}), _} = raw_recv_pase(Data1),

    % will return connack with success
    Packet2 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                                              'Authentication-Data'   => <<"ok">>})),
    emqx_client_sock:send(Sock, Packet2),
    {ok, Data2} = gen_tcp:recv(Sock, 0),
    {ok, ?CONNACK_PACKET(?RC_SUCCESS), _} = raw_recv_pase(Data2),  

    % will return auth with continue
    Packet3 = raw_send_serialise(?AUTH_PACKET(?RC_RE_AUTHENTICATE, #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                                        'Authentication-Data'   => <<"continue">>})),
    emqx_client_sock:send(Sock, Packet3),
    {ok, Data3} = gen_tcp:recv(Sock, 0),
    {ok, ?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' := <<"TEST-AUTH">>,
                                                   'Authentication-Data'   := <<"this is a test auth">>}), _} = raw_recv_pase(Data3),  

    % will return auth with success
    Packet4 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                                              'Authentication-Data'   => <<"ok">>})),
    emqx_client_sock:send(Sock, Packet4),
    {ok, Data4} = gen_tcp:recv(Sock, 0),
    {ok, ?AUTH_PACKET(?RC_SUCCESS), _} = raw_recv_pase(Data4), 

    emqx_client_sock:close(Sock),
    ok = emqx_auth_username:remove_user(<<"admin">>).

t_auth_protocol(_Config) ->
    ok = emqx_auth_username:add_user(<<"admin">>, <<"public">>),
    % will return connack with success
    {ok, Sock} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                                        client_id   = <<"mqtt_client">>,
                                                        proto_ver   = ?MQTT_PROTO_V5,
                                                        clean_start = false,
                                                        username    = <<"admin">>,
                                                        password    = <<"public">>})),

    emqx_client_sock:send(Sock, Packet),
    {ok, Data} = gen_tcp:recv(Sock, 0),
    {ok, ?CONNACK_PACKET(?RC_SUCCESS), _} = raw_recv_pase(Data),

    % will return disconnect
    Packet1 = raw_send_serialise(?AUTH_PACKET(?RC_RE_AUTHENTICATE, #{'Authentication-Method' => <<"PLAIN">>,
                                                                     'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                                  0,112,117,98,108,105,99>>})),

    emqx_client_sock:send(Sock, Packet1),
    {ok, Data1} = gen_tcp:recv(Sock, 0),
    {ok, ?DISCONNECT_PACKET(?RC_PROTOCOL_ERROR), _} = raw_recv_pase(Data1),
    emqx_client_sock:close(Sock),

    % connection will be closed
    {ok, Sock2} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet2 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' => <<"PLAIN">>,
                                                                           'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                                        0,112,117,98,108,105,99>>})),

    emqx_client_sock:send(Sock2, Packet2),
    {error, closed} = gen_tcp:recv(Sock2, 0),
    emqx_client_sock:close(Sock2),

    {ok, Sock3} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet3 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                        'Authentication-Data'   => <<"continue">>}})),
    emqx_client_sock:send(Sock3, Packet3),
    {ok, Data3} = gen_tcp:recv(Sock3, 0),
    {ok, ?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' := <<"TEST-AUTH">>,
                                                   'Authentication-Data'   := <<"this is a test auth">>}), _} = raw_recv_pase(Data3),

    Packet4 = raw_send_serialise(?AUTH_PACKET(?RC_RE_AUTHENTICATE, #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                                     'Authentication-Data'   => <<"ok">>})),
    emqx_client_sock:send(Sock3, Packet4),
    {ok, Data4} = gen_tcp:recv(Sock3, 0),
    {ok, ?CONNACK_PACKET(?RC_PROTOCOL_ERROR), _} = raw_recv_pase(Data4), 
    emqx_client_sock:close(Sock3),

    {ok, Sock5} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet5 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' => <<"PLAIN">>,
                                                                           'Authentication-Data'   => <<0,97,100,109,105,110,
                                                                                                        0,112,117,98,108,105,99>>})),

    emqx_client_sock:send(Sock5, Packet5),
    {error, closed} = gen_tcp:recv(Sock5, 0),
    emqx_client_sock:close(Sock5),

    {ok, Sock6} = emqx_client_sock:connect({127,0,0,1}, 1883, [binary, {packet, raw}, {active, false}], 3000),
    Packet6 = raw_send_serialise(?CONNECT_PACKET(#mqtt_packet_connect{
                                        client_id   = <<"mqtt_client">>,
                                        proto_ver   = ?MQTT_PROTO_V5,
                                        clean_start = false,
                                        properties  = #{'Authentication-Method' => <<"TEST-AUTH">>,
                                                        'Authentication-Data'   => <<"continue">>}})),
    emqx_client_sock:send(Sock6, Packet6),
    {ok, Data6} = gen_tcp:recv(Sock6, 0),
    {ok, ?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE, #{'Authentication-Method' := <<"TEST-AUTH">>,
                                                   'Authentication-Data'   := <<"this is a test auth">>}), _} = raw_recv_pase(Data6),

    Packet7 = raw_send_serialise(?AUTH_PACKET(?RC_CONTINUE_AUTHENTICATE)),
    emqx_client_sock:send(Sock6, Packet7),
    {ok, Data7} = gen_tcp:recv(Sock6, 0),
    {ok, ?CONNACK_PACKET(?RC_MALFORMED_PACKET), _} = raw_recv_pase(Data7), 
    emqx_client_sock:close(Sock6),
    ok = emqx_auth_username:remove_user(<<"admin">>).

change_config(_Config) ->
    application:stop(emqx_auth_username),
    application:set_env(emqx_auth_username, userlist,
                        [{"id", "password"}, {"dev:devid", "passwd2"}]),
    application:start(emqx_auth_username),
    User1 = #{username => <<"id">>},
    User2 = #{username => <<"dev:devid">>},
    ok = emqx_access_control:authenticate(User1, <<"password">>),
    {error, password_error} = emqx_access_control:authenticate(User1, <<"password00">>),
    ok = emqx_access_control:authenticate(User2, <<"passwd2">>),
    %% clean data
    ok = emqx_auth_username:remove_user(<<"id">>),
    ok = emqx_auth_username:remove_user(<<"dev:devid">>).

cli(_Config) ->
    ok = emqx_auth_username:cli(["add", "username", "password"]),
    [{?TAB, <<"username">>, _M}] =
        emqx_auth_username:lookup_user(<<"username">>),
    ok = emqx_auth_username:cli(["del", "username"]),
    [] = emqx_auth_username:lookup_user(<<"username">>),

    ok = emqx_auth_username:cli(["add", "user1", "pass1"]),
    ok = emqx_auth_username:cli(["add", "user2", "pass2"]),
    UserList = emqx_auth_username:cli(["list"]),
    2 = length(UserList),
    emqx_auth_username:cli(usage).

start_apps(App, DataDir) ->
    Schema = cuttlefish_schema:files([filename:join([DataDir, atom_to_list(App) ++ ".schema"])]),
    Conf = conf_parse:file(filename:join([DataDir, atom_to_list(App) ++ ".conf"])),
    NewConfig = cuttlefish_generator:map(Schema, Conf),
    Vals = proplists:get_value(App, NewConfig, []),
    [application:set_env(App, Par, Value) || {Par, Value} <- Vals],
    application:ensure_all_started(App).

raw_send_serialise(Packet) ->
    emqx_frame:serialize(Packet, #{max_packet_size => ?MAX_PACKET_SIZE,
                                   version         => ?MQTT_PROTO_V5}).

raw_recv_pase(P) ->
    emqx_frame:parse(P, {none, #{max_packet_size => ?MAX_PACKET_SIZE,
                                 version         => ?MQTT_PROTO_V5} }).
