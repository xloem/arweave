-module(ar_mine_vdf_tests).

-include_lib("eunit/include/eunit.hrl").

-include_lib("arweave/include/ar_mine.hrl").

-define(ENCODED_WALLET, <<"UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM">>).
-define(ENCODED_PREV_STATE, <<"f_z7RLug8etm3SrmRf-xPwXEL0ZQ_xHng2A5emRDQBw">>).

soft_implementation_vdf(Wallet, PrevState, 0) ->
	crypto:hash(sha256, <<Wallet/binary, PrevState/binary>>);

soft_implementation_vdf(Wallet, PrevState, Iterations) ->
	NextState = crypto:hash(sha256, <<Wallet/binary, PrevState/binary>>),
	soft_implementation_vdf(Wallet, NextState, Iterations-1).

vdf_suite_test_() ->
	{timeout, 500, fun test_vdf_/0}.

test_vdf_() ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	Real = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, 10),
	ExpectedHash = soft_implementation_vdf(Wallet, PrevState, 10),
	?assertEqual(ExpectedHash, Real).
