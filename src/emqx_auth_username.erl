%%--------------------------------------------------------------------
%% Copyright (c) 2013-2018 EMQ Enterprise, Inc. (http://emqtt.io)
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
%%--------------------------------------------------------------------

-module(emqx_auth_username).

-behaviour(emqx_auth_mod).

-include ("emqx_auth_username.hrl").

-include_lib("emqx/include/emqx.hrl").

-include_lib("emqx/include/emqx_cli.hrl").

-include_lib("emqx/include/emqx_internal.hrl").

%% CLI callbacks
-export([cli/1]).

-export([is_enabled/0]).

-export([add_user/2, remove_user/1, lookup_user/1, all_users/0]).

%% emqx_auth callbacks
-export([init/1, check/3, description/0]).

-define(AUTH_USERNAME_TAB, mqtt_auth_username).

%%--------------------------------------------------------------------
%% CLI
%%--------------------------------------------------------------------

cli(["list"]) ->
    if_enabled(fun() ->
        Usernames = mnesia:dirty_all_keys(?AUTH_USERNAME_TAB),
        [?PRINT("~s~n", [Username]) || Username <- Usernames]
    end);

cli(["add", Username, Password]) ->
    if_enabled(fun() ->
        ?PRINT("~p~n", [add_user(iolist_to_binary(Username), iolist_to_binary(Password))])
    end);

cli(["del", Username]) ->
    if_enabled(fun() ->
        ?PRINT("~p~n", [remove_user(iolist_to_binary(Username))])
    end);

cli(_) ->
    ?USAGE([{"users list", "List users"},
            {"users add <Username> <Password>", "Add User"},
            {"users del <Username>", "Delete User"}]).

if_enabled(Fun) ->
    case is_enabled() of
        true  -> Fun();
        false -> hint()
    end.

hint() ->
    ?PRINT_MSG("Please './bin/emqx_ctl plugins load emqx_auth_username' first.~n").

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

is_enabled() ->
    lists:member(?AUTH_USERNAME_TAB, mnesia:system_info(tables)).

%% @doc Add User
-spec(add_user(binary(), binary()) -> ok | {error, any()}).
add_user(Username, Password) ->
    User = #?AUTH_USERNAME_TAB{username = Username, password = hash(Password)},
    ret(mnesia:transaction(fun insert_user/1, [User])).

insert_user(User = #?AUTH_USERNAME_TAB{username = Username}) ->
    case mnesia:read(?AUTH_USERNAME_TAB, Username) of
        []    -> mnesia:write(User);
        [_|_] -> mnesia:abort(existed)
    end.

%% @doc Lookup user by username
-spec(lookup_user(binary()) -> list()).
lookup_user(Username) ->
    mnesia:dirty_read(?AUTH_USERNAME_TAB, Username).

%% @doc Remove user
-spec(remove_user(binary()) -> ok | {error, any()}).
remove_user(Username) ->
    ret(mnesia:transaction(fun delete_user/1, [Username])).

delete_user(Username) ->
    case mnesia:read(?AUTH_USERNAME_TAB, Username) of
        []  -> mnesia:abort(not_existed);
        [_] -> mnesia:delete({?AUTH_USERNAME_TAB, Username})
    end.


ret({atomic, ok})     -> ok;
ret({aborted, Error}) -> {error, Error}.

%% @doc All usernames
-spec(all_users() -> list()).
all_users() -> mnesia:dirty_all_keys(?AUTH_USERNAME_TAB).

%%--------------------------------------------------------------------
%% emqx_auth_mod callbacks
%%--------------------------------------------------------------------

init(_) ->
    ok = ekka_mnesia:create_table(?AUTH_USERNAME_TAB, [
            {disc_copies, [node()]},
            {attributes, record_info(fields, ?AUTH_USERNAME_TAB)}]),
    ok = ekka_mnesia:copy_table(?AUTH_USERNAME_TAB, disc_copies),
    emqx_ctl:register_cmd(users, {?MODULE, cli}, []),
    {ok, undefined}.

check(#mqtt_client{username = undefined}, _Password, _Opts) ->
    {error, username_undefined};
check(_User, undefined, _Opts) ->
    {error, password_undefined};
check(#mqtt_client{username = Username}, Password, _Opts) ->
    case mnesia:dirty_read(?AUTH_USERNAME_TAB, Username) of
        [] ->
            ignore;
        [#?AUTH_USERNAME_TAB{password = HashPassword}] ->
            case HashPassword =:= hash(Password) of
                true -> ok;
                false -> {error, password_error}
            end
    end.

description() ->
    "Username password authentication module".

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
hash(Password) ->
    emqx_auth_mod:passwd_hash(list_to_atom(application:get_env(emqx_auth_username, password_hash, plain)), Password).

