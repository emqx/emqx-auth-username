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

-module(emqx_auth_username).

-behaviour(emqx_auth_mod).

-include_lib("emqx/include/emqx.hrl").

%% CLI callbacks
-export([cli/1]).
-export([is_enabled/0]).
-export([add_user/2, remove_user/1, lookup_user/1, all_users/0]).
%% emqx_auth callbacks
-export([init/1, check/3, description/0]).

-define(TAB, ?MODULE).
-record(?TAB, {username, password}).

%%-----------------------------------------------------------------------------
%% CLI
%%-----------------------------------------------------------------------------

cli(["list"]) ->
    if_enabled(fun() ->
        Usernames = mnesia:dirty_all_keys(?TAB),
        [emqx_cli:print("~s~n", [Username]) || Username <- Usernames]
    end);

cli(["add", Username, Password]) ->
    if_enabled(fun() ->
        Ok = add_user(iolist_to_binary(Username), iolist_to_binary(Password)),
        emqx_cli:print("~p~n", [Ok])
    end);

cli(["del", Username]) ->
    if_enabled(fun() ->
        emqx_cli:print("~p~n", [remove_user(iolist_to_binary(Username))])
    end);

cli(_) ->
    emqx_cli:usage([{"users list", "List users"},
                    {"users add <Username> <Password>", "Add User"},
                    {"users del <Username>", "Delete User"}]).

if_enabled(Fun) ->
    case is_enabled() of true -> Fun(); false -> hint() end.

hint() ->
    emqx_cli:print("Please './bin/emqx_ctl plugins load emqx_auth_username' first.~n").

%%-----------------------------------------------------------------------------
%% API
%%-----------------------------------------------------------------------------

is_enabled() ->
    lists:member(?TAB, mnesia:system_info(tables)).

%% @doc Add User
-spec(add_user(binary(), binary()) -> ok | {error, any()}).
add_user(Username, Password) ->
    User = #?TAB{username = Username, password = hash(Password)},
    ret(mnesia:transaction(fun insert_user/1, [User])).

insert_user(User = #?TAB{username = Username}) ->
    case mnesia:read(?TAB, Username) of
        []    -> mnesia:write(User);
        [_|_] -> mnesia:abort(existed)
    end.

add_default_user({Username, Password}) when is_atom(Username) ->
    add_default_user({atom_to_list(Username), Password});

add_default_user({Username, Password}) ->
    add_user(iolist_to_binary(Username), iolist_to_binary(Password)).

%% @doc Lookup user by username
-spec(lookup_user(binary()) -> list()).
lookup_user(Username) ->
    mnesia:dirty_read(?TAB, Username).

%% @doc Remove user
-spec(remove_user(binary()) -> ok | {error, any()}).
remove_user(Username) ->
    ret(mnesia:transaction(fun mnesia:delete/1, [{?TAB, Username}])).

ret({atomic, ok})     -> ok;
ret({aborted, Error}) -> {error, Error}.

%% @doc All usernames
-spec(all_users() -> list()).
all_users() -> mnesia:dirty_all_keys(?TAB).

%%-----------------------------------------------------------------------------
%% emqx_auth_mod callbacks
%%-----------------------------------------------------------------------------

init(Userlist) ->
    ok = ekka_mnesia:create_table(?TAB, [
            {disc_copies, [node()]},
            {attributes, record_info(fields, ?TAB)}]),
    ok = ekka_mnesia:copy_table(?TAB, disc_copies),
    ok = lists:foreach(fun add_default_user/1, Userlist),
    {ok, undefined}.

check(#{auth_method := <<"PLAIN">>, auth_data := AuthData}, _Password, _Opts)
    when AuthData =:= undefined orelse AuthData =:= <<>> ->
    {error, invalid_auth_data};
check(#{username := Username, auth_method := <<"PLAIN">>, auth_data := AuthData}, _Password, _Opts) ->
    case binary:split(AuthData, <<0>>, [global, trim]) of
        [_, Username1, Password] -> 
            Username2 = case Username of 
                            undefined ->
                                Username1;
                            _->
                                Username
                        end,
            case mnesia:dirty_read(?TAB, Username2) of
                [] -> ignore;
                [#?TAB{password = <<Salt:4/binary, Hash/binary>>}] ->
                    case Hash =:= md5_hash(Salt, Password) of
                        true -> {ok, #{username => Username2}};
                        false -> {error, password_error}
                    end
            end;
        _ ->
            {error, invalid_auth_data}
    end;
check(#{auth_method := <<"PLAIN">>}, _Password, _Opts) ->
    {error, invalid_auth_data};
check(#{auth_method := _AuthMethod}, _Password, _Opts) ->
    {error, bad_authentication_method};
check(#{username := undefined}, _Password, _Opts) ->
    {error, username_undefined};
check(_Credentials, undefined, _Opts) ->
    {error, password_undefined};
check(#{username := Username}, Password, _Opts) ->
    case mnesia:dirty_read(?TAB, Username) of
        [] -> ignore;
        [#?TAB{password = <<Salt:4/binary, Hash/binary>>}] ->
            case Hash =:= md5_hash(Salt, Password) of
                true -> ok;
                false -> {error, password_error}
            end
    end.

description() ->
    "Username password Authentication Module".

%%-----------------------------------------------------------------------------
%% Internal functions
%%-----------------------------------------------------------------------------

hash(Password) ->
    SaltBin = salt(), <<SaltBin/binary, (md5_hash(SaltBin, Password))/binary>>.

md5_hash(SaltBin, Password) ->
    erlang:md5(<<SaltBin/binary, Password/binary>>).

salt() ->
    emqx_time:seed(), Salt = rand:uniform(16#ffffffff), <<Salt:32>>.

