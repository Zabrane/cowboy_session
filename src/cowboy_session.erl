-module(cowboy_session).

%% API
-export([
    start/0,
    on_request/1,
    get/2, get/3,
    set/3,
    delete/2,
    expire/1,
    get_session/1,
    touch/1
]).

%% API 2
-export([
    get_ssid/1,
    get_session_pid/1,
    get2/2, get2/3,
    set2/3,
    delete2/2,
    expire2/1
]).

-behaviour(application).
-export([start/2, stop/1]).

-behaviour(supervisor).
-export([init/1]).

%% Config
-include("cowboy_session_config.hrl").

%% ===================================================================
%% API functions
%% ===================================================================

-spec start() -> ok.
start() ->
    ensure_started([?MODULE]).

-spec on_request(cowboy_req:req()) -> cowboy_req:req().
on_request(Req) ->
    {_Session, _SID, Req2} = get_session(Req),
    Req2.

get2(Key, SID) ->
    get2(Key, undefined, SID).

get2(Key, Default, SID) ->
    Pid = get_session_server_pid_and_touch(SID),
    cowboy_session_server:get(Pid, Key, Default).

get(Key, Req) ->
    get(Key, undefined, Req).

get(Key, Default, Req) ->
    {Pid, _SID, Req2} = get_session(Req),
    Value = cowboy_session_server:get(Pid, Key, Default),
    {Value, Req2}.

set(Key, Value, Req) ->
    {Pid, _SID, Req2} = get_session(Req),
    cowboy_session_server:set(Pid, Key, Value),
    {ok, Req2}.

set2(Key, Value, SID) ->
    Pid = get_session_server_pid_and_touch(SID),
    cowboy_session_server:set(Pid, Key, Value),
    ok.

delete(Key, Req) ->
    {Pid, _SID, Req2} = get_session(Req),
    cowboy_session_server:delete(Pid, Key),
    {ok, Req2}.

delete2(Key, SID) ->
    Pid = get_session_server_pid_and_touch(SID),
    cowboy_session_server:delete(Pid, Key),
    ok.

expire(Req) ->
    {Pid, _SID, Req2} = get_session(Req),
    cowboy_session_server:stop(Pid),
    Req3 = clear_cookie(Req2),
    {ok, Req3}.

expire2(SID) ->
    Pid = get_session_server_pid_and_touch(SID),
    cowboy_session_server:stop(Pid),
    ok.

touch(Req) ->
    {_Pid, _SID, Req2} = get_session(Req),
    {ok, Req2}.

get_session_pid(SID) ->
    gproc:lookup_local_name(?SESSION_SERVER_ID(SID)).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    {ok, Sup} = supervisor:start_link({local, ?MODULE}, ?MODULE, []),
    supervisor:start_child(Sup, ?CHILD(?CONFIG(storage, cowboy_session_storage_ets), worker)),
    {ok, Sup}.

stop(_State) ->
    ok.

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    Restart_strategy = {one_for_one, 10, 5},
    Children = [
        ?CHILD(cowboy_session_server_sup, supervisor)
    ],
    {ok, {Restart_strategy, Children}}.

%% ===================================================================
%% Internal functions
%% ===================================================================

get_session_server_pid_and_touch(SID) ->
    case gproc:lookup_local_name(?SESSION_SERVER_ID(SID)) of
        undefined ->
            throw({process_not_registered, ?SESSION_SERVER_ID(SID)});
        Pid ->
            cowboy_session_server:touch(Pid),
            Pid
    end.

get_ssid(Req) ->
    Cookie_name = ?CONFIG(session, <<"session">>),
    CookieNameAtom = erlang:binary_to_atom(Cookie_name, unicode),
    #{CookieNameAtom := SID} = cowboy_req:match_cookies([{CookieNameAtom, [], undefined}], Req),
    SID.

get_session(Req) ->
    Cookie_name = ?CONFIG(session, <<"session">>),
    CookieNameAtom = erlang:binary_to_atom(Cookie_name, unicode),
    #{CookieNameAtom := SID} = cowboy_req:match_cookies([{CookieNameAtom, [], undefined}], Req),
    case SID of
        undefined ->
            create_session(Req);
        _ ->
            case gproc:lookup_local_name(?SESSION_SERVER_ID(SID)) of
                undefined ->
                    create_session(Req);
                Pid ->
                    cowboy_session_server:touch(Pid),
                    {Pid, SID, Req}
            end
    end.

clear_cookie(Req) ->
    Cookie_name = ?CONFIG(session, <<"session">>),
    cowboy_req:set_resp_cookie(Cookie_name, <<"deleted">>, Req, #{max_age => 0}).

create_session(Req) ->
    %% The cookie value cannot contain any of the following characters:
    %%   ,; \t\r\n\013\014
    SID = list_to_binary(uuid:uuid_to_string(uuid:get_v4())),
    Cookie_name = ?CONFIG(session, <<"session">>),
    Storage = ?CONFIG(storage, cowboy_session_storage_ets),
    Expire = ?CONFIG(expire, 1440),
    Cookie_options = ?CONFIG(options, #{path => <<"/">>, max_age => Expire}),
    {ok, Pid} = supervisor:start_child(cowboy_session_server_sup, [[
        {sid, SID},
        {storage, Storage},
        {expire, Expire}
    ]]),
    Req1 = cowboy_req:set_resp_cookie(Cookie_name, SID, Req, Cookie_options),
    {Pid, SID, Req1}.

ensure_started([]) -> ok;
ensure_started([App | Rest] = Apps) ->
    case application:start(App) of
        ok -> ensure_started(Rest);
        {error, {already_started, App}} -> ensure_started(Rest);
        {error, {not_started, Dependency}} -> ensure_started([Dependency | Apps])
    end.
