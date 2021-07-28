%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(erlesys).

%% API
-export([initialize/1, finalize/0, get_capability/6, evict_control/6, tr_from_tpm_public/4]).

-on_load(init/0).

init() ->
    SoName = case code:priv_dir(erltss2) of
                 {error, bad_name} ->
                     erlang:display("_______________bad_name______________"),
                     case filelib:is_dir(filename:join(["..", priv])) of
                         true ->
                             filename:join(["..", priv, ?MODULE]);
                         false ->
                             filename:join([priv, ?MODULE])
                     end;
                 Dir ->
                     erlang:display("_______________success______________"),
                     filename:join(Dir, ?MODULE)
             end,
    ok = erlang:load_nif(SoName, 0).



initialize(_Tcti) ->
    erlang:error(not_implemented).

finalize() ->
    erlang:error(not_implemented).

get_capability(_SHandle1, _SHandle2, _SHandle3, _Capability, _Property, _PropertyCount) ->
    erlang:error(not_implemented).

evict_control(_Auth, _Handle, _SHandle1, _SHandle2, _SHandle3, _PersistentHandle) ->
    erlang:error(not_implemented).

tr_from_tpm_public(_Handle, _SHandle1, _SHandle2, _SHandle3) ->
    erlang:error(not_implemented).