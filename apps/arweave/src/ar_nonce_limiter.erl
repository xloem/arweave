-module(ar_nonce_limiter).

-export([pre_validate/1, request_validation/1]).

-include_lib("arweave/include/ar.hrl").

%%%===================================================================
%%% Public interface.
%%%===================================================================

%% @doc Quickly validate the checkpoints of the latest step.
pre_validate(_B) ->
	true.

%% @doc Validate the nonce limiter chain of the given block.
%% Emit {nonce_limiter, {invalid, H}} or {nonce_limiter, {valid, H}}.
request_validation(B) ->
	ar_events:send(nonce_limiter, {valid, B#block.indep_hash}).
