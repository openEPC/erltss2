%%%-------------------------------------------------------------------
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(erlfapi).

%% API
-export([fapi_Initialize/1, fapi_Finalize/0, fapi_Provision/3, fapi_CreateKey/4, fapi_Sign/3, fapi_VerifySignature/5, fapi_ECDHZGen/3, fapi_GetPublicKeyECC/1]).

-on_load(init/0).

init() ->
  ok = erlang:load_nif("liberlfapi", 0).


fapi_Initialize(_) ->
  exit(nif_library_not_loaded).
fapi_Finalize() ->
  exit(nif_library_not_loaded).
fapi_Provision(_,_,_) ->
  exit(nif_library_not_loaded).
fapi_CreateKey(_,_,_,_) ->
  exit(nif_library_not_loaded).
fapi_Sign(_,_,_) ->
  exit(nif_library_not_loaded).
fapi_VerifySignature(_,_,_,_,_) ->
  exit(nif_library_not_loaded).
fapi_ECDHZGen(_,_,_) ->
  exit(nif_library_not_loaded).
fapi_GetPublicKeyECC(_) ->
  exit(nif_library_not_loaded).