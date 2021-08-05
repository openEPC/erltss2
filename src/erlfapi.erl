%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(erlfapi).

%% API
-export([create_key/4, delete/1, ecdh_zgen/3, finalize/0, get_public_key_ecc/1, get_tcti/0,
        initialize/1, list/1, provision/3, rc_decode/1, sign/3, verify_signature/3
         ]).

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


create_key(_Path,_Type,_PolicyPath,_Auth) ->
  exit(nif_library_not_loaded).
delete(_Path) ->
  exit(nif_library_not_loaded).
ecdh_zgen(_KeyPath,_X,_Y) ->
  exit(nif_library_not_loaded).
finalize() ->
  exit(nif_library_not_loaded).
get_public_key_ecc(_KeyPath) ->
  exit(nif_library_not_loaded).
get_tcti() ->
  exit(nif_library_not_loaded).
initialize(_Uri) ->
  exit(nif_library_not_loaded).
list(_Path) ->
  exit(nif_library_not_loaded).
provision(_AuthE,_AuthS,_AuthLock) ->
  exit(nif_library_not_loaded).
rc_decode(_ResponseCode) ->
  exit(nif_library_not_loaded).
sign(_KeyPath,_Padding,_Digest) ->
  exit(nif_library_not_loaded).
verify_signature(_KeyPath,_Digest,_Signature) ->
  exit(nif_library_not_loaded).
