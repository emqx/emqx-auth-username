%% Copyright (c) 2013-2019 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").

-define(TAB, emqx_auth_username).
-record(?TAB, {username, password}).

all() ->
    [{group, emqx_auth_username}].

groups() ->
    [{emqx_auth_username, [sequence],
      [emqx_auth_username_api, emqx_auth_username_rest_api, change_config, cli]}].

init_per_suite(Config) ->
    [start_apps(App, SchemaFile, ConfigFile) ||
        {App, SchemaFile, ConfigFile}
            <- [{emqx, deps_path(emqx, "priv/emqx.schema"),
                       deps_path(emqx, "etc/emqx.conf")},
                {emqx_auth_username, local_path("priv/emqx_auth_username.schema"),
                                     local_path("etc/emqx_auth_username.conf")}]],
    Config.

end_per_suite(_Config) ->
    application:stop(emqx_auth_username),
    application:stop(emqx).

deps_path(App, RelativePath) ->
    %% Note: not lib_dir because etc dir is not sym-link-ed to _build dir
    %% but priv dir is
    Path0 = code:priv_dir(App),
    Path = case file:read_link(Path0) of
               {ok, Resolved} -> Resolved;
               {error, _} -> Path0
           end,
    filename:join([Path, "..", RelativePath]).

local_path(RelativePath) ->
    deps_path(emqx_auth_username, RelativePath).

start_apps(App, SchemaFile, ConfigFile) ->
    read_schema_configs(App, SchemaFile, ConfigFile),
    set_special_configs(App),
    application:ensure_all_started(App).

read_schema_configs(App, SchemaFile, ConfigFile) ->
    ct:pal("Read configs - SchemaFile: ~p, ConfigFile: ~p", [SchemaFile, ConfigFile]),
    Schema = cuttlefish_schema:files([SchemaFile]),
    Conf = conf_parse:file(ConfigFile),
    NewConfig = cuttlefish_generator:map(Schema, Conf),
    Vals = proplists:get_value(App, NewConfig, []),
    [application:set_env(App, Par, Value) || {Par, Value} <- Vals].

set_special_configs(emqx) ->
    application:set_env(emqx, allow_anonymous, false),
    application:set_env(emqx, enable_acl_cache, false),
    application:set_env(emqx, plugins_loaded_file,
                        deps_path(emqx, "test/emqx_SUITE_data/loaded_plugins"));
set_special_configs(_App) ->
    ok.

emqx_auth_username_api(_Config) ->
    ok = emqx_auth_username:add_user(<<"test_username">>, <<"password">>),
    User1 = #{username => <<"test_username">>},
    [{?TAB, <<"test_username">>, _HashedPass}] =
        emqx_auth_username:lookup_user(<<"test_username">>),
    ok = emqx_access_control:authenticate(User1, <<"password">>),
    ok = emqx_auth_username:remove_user(<<"test_username">>),
    {error, _} = emqx_access_control:authenticate(User1, <<"password">>).

emqx_auth_username_rest_api(_Config) ->
    Username = <<"username">>,
    Password = <<"password">>,
    Password1 = <<"password1">>,
    User = #{username => Username},

    ?assertEqual(return(),
                 emqx_auth_username_api:add(#{}, rest_params(Username, Password))),
    ?assertEqual(return({error, existed}),
                 emqx_auth_username_api:add(#{}, rest_params(Username, Password))),
    ?assertEqual(return([Username]),
                 emqx_auth_username_api:list(#{}, [])),

    ok = emqx_access_control:authenticate(User, Password),

    ?assertEqual(return(),
                 emqx_auth_username_api:update(rest_binding(Username), rest_params(Password))),
    ?assertEqual(return({error, noexisted}),
                 emqx_auth_username_api:update(#{username => <<"another_user">>}, rest_params(<<"another_passwd">>))),

    {error, password_error} = emqx_access_control:authenticate(User, Password1),

    ?assertEqual(return(),
                 emqx_auth_username_api:delete(rest_binding(Username), [])),
    {error, _} = emqx_access_control:authenticate(User, Password).

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
    [ mnesia:dirty_delete({emqx_auth_username, Username}) ||  Username <- mnesia:dirty_all_keys(emqx_auth_username)],
    emqx_auth_username:cli(["add", "username", "password"]),
    [{?TAB, <<"username">>, <<Salt:4/binary, Hash/binary>>}] =
        emqx_auth_username:lookup_user(<<"username">>),
    HashType = application:get_env(emqx_auth_username, password_hash, sha256),
    case Hash =:= emqx_passwd:hash(HashType, <<Salt/binary, <<"password">>/binary>>) of
        true -> ok;
        false -> ct:fail("password error")
    end, 
    emqx_auth_username:cli(["update", "username", "newpassword"]),
    [{?TAB, <<"username">>, <<Salt1:4/binary, Hash1/binary>>}] =
        emqx_auth_username:lookup_user(<<"username">>),
    case Hash1 =:= emqx_passwd:hash(HashType, <<Salt1/binary, <<"newpassword">>/binary>>) of
        true -> ok;
        false -> ct:fail("password error")
    end,    
    emqx_auth_username:cli(["del", "username"]),
    [] = emqx_auth_username:lookup_user(<<"username">>),
    emqx_auth_username:cli(["add", "user1", "pass1"]),
    emqx_auth_username:cli(["add", "user2", "pass2"]),
    UserList = emqx_auth_username:cli(["list"]),
    2 = length(UserList),
    emqx_auth_username:cli(usage).

%%------------------------------------------------------------------------------
%% Helpers
%%------------------------------------------------------------------------------
rest_params(Passwd) ->
    [{<<"password">>, Passwd}].

rest_params(Username, Passwd) ->
    [{<<"username">>, Username},
     {<<"password">>, Passwd}].

rest_binding(Username) ->
    #{username => Username}.

return() ->
    {ok, [{code, 0}]}.
return({error, Err}) ->
    {ok, [{message, Err}]};
return(Data) ->
    {ok, [{code, 0}, {data, Data}]}.

