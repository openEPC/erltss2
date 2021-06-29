%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(erlfapi).

%% API
-export([fapi_Initialize/1, fapi_Finalize/0, fapi_Provision/3, fapi_CreateKey/4, fapi_Delete/1, fapi_Sign/3, fapi_VerifySignature/3, fapi_ECDHZGen/3, fapi_GetPublicKeyECC/1]).

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


fapi_Initialize(_Uri) ->
  exit(nif_library_not_loaded).
fapi_Finalize() ->
  exit(nif_library_not_loaded).
fapi_Provision(_AuthE,_AuthS,_AuthLock) ->
  exit(nif_library_not_loaded).
fapi_CreateKey(_Path,_Type,_PolicyPath,_Auth) ->
  exit(nif_library_not_loaded).
fapi_Delete(_Path) ->
  exit(nif_library_not_loaded).
fapi_Sign(_KeyPath,_Padding,_Digest) ->
  exit(nif_library_not_loaded).
fapi_VerifySignature(_KeyPath,_Digest,_Signature) ->
  exit(nif_library_not_loaded).
fapi_ECDHZGen(_KeyPath,_X,_Y) ->
  exit(nif_library_not_loaded).
fapi_GetPublicKeyECC(_KeyPath) ->
  exit(nif_library_not_loaded).