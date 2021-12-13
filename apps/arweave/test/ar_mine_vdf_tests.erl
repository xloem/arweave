-module(ar_mine_vdf_tests).

-include_lib("eunit/include/eunit.hrl").

-include_lib("arweave/include/ar_mine.hrl").

-define(ENCODED_WALLET, <<"UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM">>).
-define(ENCODED_PREV_STATE, <<"f_z7RLug8etm3SrmRf-xPwXEL0ZQ_xHng2A5emRDQBw">>).
-define(ENCODED_KEY, <<"UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM">>).

soft_implementation_vdf_sha(Wallet, PrevState, 0) ->
	crypto:hash(sha256, <<Wallet/binary, PrevState/binary>>);

soft_implementation_vdf_sha(Wallet, PrevState, Iterations) ->
	NextState = crypto:hash(sha256, <<Wallet/binary, PrevState/binary>>),
	soft_implementation_vdf_sha(Wallet, NextState, Iterations-1).

vdf_sha_test_() ->
	{timeout, 500, fun test_vdf_sha_/0}.

test_vdf_sha_() ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	{ok, Real} = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, 10),
	ExpectedHash = soft_implementation_vdf_sha(Wallet, PrevState, 10),
	?assertEqual(ExpectedHash, Real).


vdf_randomx_test_() ->
	{timeout, 500, fun test_vdf_randomx_/0}.


test_vdf_randomx_() ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	IterationsSha = 10,
	IterationsRandomx = 5,

	Key = ar_util:decode(?ENCODED_KEY),
	{ok, State} = ar_mine_randomx:init_fast_nif(Key, 0, 0, 4),

	{ok, Vm} = ar_mine_randomx:vdf_randomx_create_vm_nif(State, 1, 0, 0, 0),
	{ok, State2} = ar_mine_randomx:vdf_randomx_nif(Wallet, PrevState, IterationsRandomx, State, Vm),
	{ok, _State3} = ar_mine_randomx:vdf_randomx_nif(Wallet, State2, IterationsRandomx, State, Vm),

	{ok, StateCombo} = ar_mine_randomx:vdf_parallel_sha_randomx_nif(Wallet, PrevState, IterationsSha, IterationsRandomx, State, Vm),
	{ok, StateComboSha} = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, IterationsSha),
	ExpdNextState = crypto:hash(sha256, <<StateComboSha/binary, State2/binary>>),

	?assertEqual(ExpdNextState, StateCombo).
