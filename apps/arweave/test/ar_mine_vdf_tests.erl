-module(ar_mine_vdf_tests).

-include_lib("eunit/include/eunit.hrl").

-include_lib("arweave/include/ar_mine.hrl").

-define(ENCODED_WALLET, <<"UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM">>).
-define(ENCODED_PREV_STATE, <<"f_z7RLug8etm3SrmRf-xPwXEL0ZQ_xHng2A5emRDQBw">>).
-define(ENCODED_KEY, <<"UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM">>).
-define(MAX_THREAD_COUNT, 4).
-define(ITERATIONS_SHA, 10).
-define(ITERATIONS_RANDOMX, 8).
-define(CHECKPOINT_COUNT, 4).
-define(ENCODED_SHA_CHECKPOINT, <<"cmYWQ5jSIRJ3TQs5HEZ7yIeTE-4OgH65F2WsO5Sq9zh__C-zV6iGMxFStUHfq-veuhVJ5MVu74FbDFRVjkfbA4hDnzmFSVPUQSh5z-kCiXa8Jio6bZe80PAIPapM31Ab-kxX3E574bnH8cSOr95s-OWv6AUx-XXHxFjUXp_6_Os">>).
-define(ENCODED_SHA_RES, <<"Le7NfCA5WxsWWyQu5Nh9ynsXzVsjAFTRkA0akuC_aWg">>).
-define(ENCODED_RANDOMX_CHECKPOINT, <<"9Lk8rcTldv4T7qHttpXVq_C3jxpVYXm_fHgGA-i6K3Sc0nvf0u2EhMUdx26GBUdgM8zxijbyD_WuXOIXNbBlUBtlcGZwTpCrAjlH-C-Cw-1QIMoYCERrkfu_B3Bw0KQkPe6tyzyz5uzjrcCvJG1cxxqQcYfggS0M_8JMpV7rvmM">>).
-define(ENCODED_RANDOMX_RES, <<"BszTE2VXp9eDV8ylLoHsL_xmtwpRg4LZQZ9KpUZEF9U">>).
-define(ENCODED_SHA_RANDOMX_CHECKPOINT, <<"cmYWQ5jSIRJ3TQs5HEZ7yIeTE-4OgH65F2WsO5Sq9zh__C-zV6iGMxFStUHfq-veuhVJ5MVu74FbDFRVjkfbA4hDnzmFSVPUQSh5z-kCiXa8Jio6bZe80PAIPapM31Ab-kxX3E574bnH8cSOr95s-OWv6AUx-XXHxFjUXp_6_Ost7s18IDlbGxZbJC7k2H3KexfNWyMAVNGQDRqS4L9paPS5PK3E5Xb-E-6h7baV1avwt48aVWF5v3x4BgPouit0nNJ739LthITFHcduhgVHYDPM8Yo28g_1rlziFzWwZVAbZXBmcE6QqwI5R_gvgsPtUCDKGAhEa5H7vwdwcNCkJD3urcs8s-bs463AryRtXMcakHGH4IEtDP_CTKVe675jBszTE2VXp9eDV8ylLoHsL_xmtwpRg4LZQZ9KpUZEF9U">>).
-define(ENCODED_SHA_RANDOMX_RES, <<"mBMneW4pYE3pNr60BrUh6Lb3eHhc2L2-JZ1bCx8zQII">>).

%%%===================================================================
%%% SHA.
%%%===================================================================

soft_implementation_vdf_sha(_Wallet, PrevState, 0) ->
	PrevState;

soft_implementation_vdf_sha(Wallet, PrevState, Iterations) ->
	NextState = crypto:hash(sha256, <<Wallet/binary, PrevState/binary>>),
	soft_implementation_vdf_sha(Wallet, NextState, Iterations-1).

vdf_sha_test_() ->
	{timeout, 500, fun test_vdf_sha_/0}.

test_vdf_sha_() ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	OutCheckpointSha3 = ar_util:decode(?ENCODED_SHA_CHECKPOINT),
	RealSha3 = ar_util:decode(?ENCODED_SHA_RES),

	{ok, Real1, _OutCheckpointSha} = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, 0, ?ITERATIONS_SHA),
	ExpectedHash = soft_implementation_vdf_sha(Wallet, PrevState, ?ITERATIONS_SHA),
	?assertEqual(ExpectedHash, Real1),

	{ok, RealSha2, OutCheckpointSha2} = ar_mine_randomx:vdf_sha2_nif(Wallet, Real1, ?CHECKPOINT_COUNT-1, ?ITERATIONS_SHA),
	{ok, RealSha3, OutCheckpointSha3} = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA),
	ExpectedSha3 = soft_implementation_vdf_sha(Wallet, PrevState, (?CHECKPOINT_COUNT+1)*?ITERATIONS_SHA),
	?assertEqual(ExpectedSha3, RealSha2),
	?assertEqual(ExpectedSha3, RealSha3),
	ExpedctedOutCheckpoint3 = << Real1/binary, OutCheckpointSha2/binary >>,
	?assertEqual(ExpedctedOutCheckpoint3, OutCheckpointSha3),
	ok = ar_mine_randomx:vdf_parallel_sha_verify_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, OutCheckpointSha3, RealSha3, ?MAX_THREAD_COUNT),
	ok = test_vdf_sha_verify_break1_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, OutCheckpointSha3, RealSha3),
	ok = test_vdf_sha_verify_break2_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, OutCheckpointSha3, RealSha3),

	ok.

break_byte(Buf, Pos)->
	Head = binary:part(Buf, 0, Pos),
	Tail = binary:part(Buf, Pos+1, size(Buf)-Pos-1),
	ChangedByte = binary:at(Buf,Pos) bxor 1,
	<<Head/binary, ChangedByte, Tail/binary>>.

test_vdf_sha_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash) ->
	test_vdf_sha_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, size(OutCheckpoint)-1).

test_vdf_sha_verify_break1_(_Wallet, _PrevState, _CheckpointCount, _Iterations, _OutCheckpoint, _Hash, 0) ->
	ok;
test_vdf_sha_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, BreakPos) ->
	OutCheckpointBroken = break_byte(OutCheckpoint, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_sha_verify_nif(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpointBroken, Hash, ?MAX_THREAD_COUNT),
	test_vdf_sha_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, BreakPos-1).

test_vdf_sha_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash) ->
	test_vdf_sha_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, size(Hash)-1).

test_vdf_sha_verify_break2_(_Wallet, _PrevState, _CheckpointCount, _Iterations, _OutCheckpoint, _Hash, 0) ->
	ok;
test_vdf_sha_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, BreakPos) ->
	HashBroken = break_byte(Hash, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_sha_verify_nif(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, HashBroken, ?MAX_THREAD_COUNT),
	test_vdf_sha_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, BreakPos-1).

%%%===================================================================
%%% RandomX.
%%%===================================================================

vdf_sha_randomx_test_() ->
	{timeout, 500, fun test_vdf_randomx_sha_combined_/0}.

test_vdf_randomx_sha_combined_() ->
	Key = ar_util:decode(?ENCODED_KEY),
	{ok, State} = ar_mine_randomx:init_fast_nif(Key, 0, 0, 4),
	test_vdf_randomx_(State),
	test_vdf_sha_randomx_(State).

test_vdf_randomx_(State) ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	OutCheckpointRandomx3 = ar_util:decode(?ENCODED_RANDOMX_CHECKPOINT),
	RealRandomx3 = ar_util:decode(?ENCODED_RANDOMX_RES),

	{ok, Vm} = ar_mine_randomx:vdf_randomx_create_vm_nif(State, 1, 0, 0, 0),

	{ok, RealRandomx1, _OutCheckpointRandomx} = ar_mine_randomx:vdf_randomx_nif(Wallet, PrevState, 0, ?ITERATIONS_RANDOMX, State, Vm),
	{ok, RealRandomx2, OutCheckpointRandomx2} = ar_mine_randomx:vdf_randomx_nif(Wallet, RealRandomx1, ?CHECKPOINT_COUNT-1, ?ITERATIONS_RANDOMX, State, Vm),
	{ok, RealRandomx3, OutCheckpointRandomx3} = ar_mine_randomx:vdf_randomx_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_RANDOMX, State, Vm),
	?assertEqual(RealRandomx2, RealRandomx3),
	ExpdOutCheckpointRandomx3 = << RealRandomx1/binary, OutCheckpointRandomx2/binary >>,
	?assertEqual(ExpdOutCheckpointRandomx3, OutCheckpointRandomx3),

	ok = ar_mine_randomx:vdf_parallel_randomx_verify_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_RANDOMX, OutCheckpointRandomx3, RealRandomx3, ?MAX_THREAD_COUNT, State, Vm),
	ok = test_vdf_randomx_verify_break1_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_RANDOMX, OutCheckpointRandomx3, RealRandomx3, State, Vm),
	ok = test_vdf_randomx_verify_break2_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_RANDOMX, OutCheckpointRandomx3, RealRandomx3, State, Vm),

	ok.

test_vdf_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm) ->
	test_vdf_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, size(OutCheckpoint)-1).

test_vdf_randomx_verify_break1_(_Wallet, _PrevState, _CheckpointCount, _Iterations, _OutCheckpoint, _Hash, _State, _Vm, 0) ->
	ok;
test_vdf_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, BreakPos) ->
	OutCheckpointBroken = break_byte(OutCheckpoint, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_randomx_verify_nif(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpointBroken, Hash, ?MAX_THREAD_COUNT, State, Vm),
	test_vdf_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, BreakPos-1).

test_vdf_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm) ->
	test_vdf_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, size(Hash)-1).

test_vdf_randomx_verify_break2_(_Wallet, _PrevState, _CheckpointCount, _Iterations, _OutCheckpoint, _Hash, _State, _Vm, 0) ->
	ok;
test_vdf_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, BreakPos) ->
	HashBroken = break_byte(Hash, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_randomx_verify_nif(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, HashBroken, ?MAX_THREAD_COUNT, State, Vm),
	test_vdf_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, Iterations, OutCheckpoint, Hash, State, Vm, BreakPos-1).


%%%===================================================================
%%% SHA+RandomX.
%%%===================================================================

test_vdf_sha_randomx_(State) ->
	Wallet = ar_util:decode(?ENCODED_WALLET),
	PrevState = ar_util:decode(?ENCODED_PREV_STATE),
	OutCheckpointCombo = ar_util:decode(?ENCODED_SHA_RANDOMX_CHECKPOINT),
	RealCombo = ar_util:decode(?ENCODED_SHA_RANDOMX_RES),

	{ok, Vm} = ar_mine_randomx:vdf_randomx_create_vm_nif(State, 1, 0, 0, 0),

	{ok, RealSha, OutCheckpointSha} = ar_mine_randomx:vdf_sha2_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA),
	{ok, RealRandomx, OutCheckpointRandomx} = ar_mine_randomx:vdf_randomx_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_RANDOMX, State, Vm),

	{ok, RealCombo, OutCheckpointCombo} = ar_mine_randomx:vdf_parallel_sha_randomx_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, ?ITERATIONS_RANDOMX, State, Vm),
	ExpdRealCombo = crypto:hash(sha256, <<RealSha/binary, RealRandomx/binary>>),
	?assertEqual(ExpdRealCombo, RealCombo),

	ExpdCheckpointCombo = << OutCheckpointSha/binary, RealSha/binary, OutCheckpointRandomx/binary, RealRandomx/binary >>,
	?assertEqual(ExpdCheckpointCombo, OutCheckpointCombo),

	ok = ar_mine_randomx:vdf_parallel_sha_randomx_verify_nif(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, ?ITERATIONS_RANDOMX, OutCheckpointCombo, RealCombo, ?MAX_THREAD_COUNT, State, Vm),
	ok = test_vdf_sha_randomx_verify_break1_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, ?ITERATIONS_RANDOMX, OutCheckpointCombo, RealCombo, State, Vm),
	ok = test_vdf_sha_randomx_verify_break2_(Wallet, PrevState, ?CHECKPOINT_COUNT, ?ITERATIONS_SHA, ?ITERATIONS_RANDOMX, OutCheckpointCombo, RealCombo, State, Vm),

	ok.

test_vdf_sha_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm) ->
	test_vdf_sha_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, size(OutCheckpoint)-1).

test_vdf_sha_randomx_verify_break1_(_Wallet, _PrevState, _CheckpointCount, _IterationsSha, _IterationsRandomx, _OutCheckpoint, _Hash, _State, _Vm, 0) ->
	ok;
test_vdf_sha_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, BreakPos) ->
	OutCheckpointBroken = break_byte(OutCheckpoint, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_sha_randomx_verify_nif(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpointBroken, Hash, ?MAX_THREAD_COUNT, State, Vm),
	test_vdf_sha_randomx_verify_break1_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, BreakPos-1).

test_vdf_sha_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm) ->
	test_vdf_sha_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, size(Hash)-1).

test_vdf_sha_randomx_verify_break2_(_Wallet, _PrevState, _CheckpointCount, _IterationsSha, _IterationsRandomx, _OutCheckpoint, _Hash, _State, _Vm, 0) ->
	ok;
test_vdf_sha_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, BreakPos) ->
	HashBroken = break_byte(Hash, BreakPos),
	{error, _} = ar_mine_randomx:vdf_parallel_sha_randomx_verify_nif(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, HashBroken, ?MAX_THREAD_COUNT, State, Vm),
	test_vdf_sha_randomx_verify_break2_(Wallet, PrevState, CheckpointCount, IterationsSha, IterationsRandomx, OutCheckpoint, Hash, State, Vm, BreakPos-1).
