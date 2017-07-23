-module(emq_auth_username_SUITE).

-compile(export_all).

-include_lib("emqttd/include/emqttd.hrl").

-include_lib("common_test/include/ct.hrl").

-record(mqtt_auth_username, {username, password}).

all() ->
    [{group, emq_auth_username}].

groups() -> 
    [{emq_auth_username, [sequence], 
      [emq_auth_username_api, change_config, cli]}].

init_per_suite(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    [start_apps(App, DataDir) || App <- [emqttd, emq_auth_username]],
    Config.

end_per_suite(_Config) ->
    application:stop(emq_auth_username),
    application:stop(emqttd).


emq_auth_username_api(_Config) ->
    ok = emq_auth_username:add_user(<<"emq_auth_username">>, <<"password">>),
    User1 = #mqtt_client{username= <<"emq_auth_username">>},
    [{mqtt_auth_username, <<"emq_auth_username">>, _P}] = 
    emq_auth_username:lookup_user(<<"emq_auth_username">>),
    ok = emqttd_access_control:auth(User1, <<"password">>),
    ok = emq_auth_username:remove_user(<<"emq_auth_username">>),
    ok = emqttd_access_control:auth(User1, <<"password">>).

change_config(_Config) ->
    application:stop(emq_auth_username),
    application:set_env(emq_auth_username, userlist, [{"id", "password"}, {"dev:devid", "passwd2"}]),
    application:start(emq_auth_username),
    User1 = #mqtt_client{username= <<"id">>},
    User2 = #mqtt_client{username= <<"dev:devid">>},
    ok = emqttd_access_control:auth(User1, <<"password">>),
    ok = emqttd_access_control:auth(User2, <<"passwd2">>).

cli(_Config) ->
    ok = emq_auth_username:cli(["add", "username", "password"]),
    [{mqtt_auth_username, <<"username">>, _M}] = 
    emq_auth_username:lookup_user(<<"username">>),
    ok = emq_auth_username:cli(["del", "username"]),
    [] = emq_auth_username:lookup_user(<<"username">>),
    emq_auth_username:cli(["list"]),
    emq_auth_username:cli(usage).

start_apps(App, DataDir) ->
    Schema = cuttlefish_schema:files([filename:join([DataDir, atom_to_list(App) ++ ".schema"])]),
    Conf = conf_parse:file(filename:join([DataDir, atom_to_list(App) ++ ".conf"])),
    NewConfig = cuttlefish_generator:map(Schema, Conf),
    Vals = proplists:get_value(App, NewConfig, []),
    [application:set_env(App, Par, Value) || {Par, Value} <- Vals],
    application:ensure_all_started(App).

