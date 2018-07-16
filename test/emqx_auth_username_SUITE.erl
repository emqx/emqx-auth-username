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

-include_lib("common_test/include/ct.hrl").

-record(mqtt_auth_username, {username, password}).

all() ->
    [{group, emqx_auth_username}].

groups() ->
    [{emqx_auth_username, [sequence],
      [emqx_auth_username_api, change_config, cli]}].

init_per_suite(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    [start_apps(App, DataDir) || App <- [emqx, emqx_auth_username]],
    Config.

end_per_suite(_Config) ->
    application:stop(emqx_auth_username),
    application:stop(emqx).

emqx_auth_username_api(_Config) ->
    ok = emqx_auth_username:add_user(<<"emqx_auth_username">>, <<"password">>),
    User1 = #mqtt_client{username= <<"emqx_auth_username">>},
    [{mqtt_auth_username, <<"emqx_auth_username">>, _P}] =
    emqx_auth_username:lookup_user(<<"emqx_auth_username">>),
    ok = emqx_access_control:auth(User1, <<"password">>),
    ok = emqx_auth_username:remove_user(<<"emqx_auth_username">>),
    ok = emqx_access_control:auth(User1, <<"password">>).

change_config(_Config) ->
    application:stop(emqx_auth_username),
    application:set_env(emqx_auth_username, userlist, [{"id", "password"}, {"dev:devid", "passwd2"}]),
    application:start(emqx_auth_username),
    User1 = #mqtt_client{username= <<"id">>},
    User2 = #mqtt_client{username= <<"dev:devid">>},
    ok = emqx_access_control:auth(User1, <<"password">>),
    ok = emqx_access_control:auth(User2, <<"passwd2">>).

cli(_Config) ->
    ok = emqx_auth_username:cli(["add", "username", "password"]),
    [{mqtt_auth_username, <<"username">>, _M}] =
    emqx_auth_username:lookup_user(<<"username">>),
    ok = emqx_auth_username:cli(["del", "username"]),
    [] = emqx_auth_username:lookup_user(<<"username">>),
    emqx_auth_username:cli(["list"]),
    emqx_auth_username:cli(usage).

start_apps(App, DataDir) ->
    Schema = cuttlefish_schema:files([filename:join([DataDir, atom_to_list(App) ++ ".schema"])]),
    Conf = conf_parse:file(filename:join([DataDir, atom_to_list(App) ++ ".conf"])),
    NewConfig = cuttlefish_generator:map(Schema, Conf),
    Vals = proplists:get_value(App, NewConfig, []),
    [application:set_env(App, Par, Value) || {Par, Value} <- Vals],
    application:ensure_all_started(App).

