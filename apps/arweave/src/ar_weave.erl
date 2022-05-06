-module(ar_weave).

-export([init/0, init/1, init/2, init/3, init/4, create_genesis_txs/0, read_v1_genesis_txs/0]).

-include_lib("arweave/include/ar.hrl").
-include_lib("arweave/include/ar_config.hrl").
-include_lib("arweave/include/ar_pricing.hrl").

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Public interface.
%%%===================================================================

%% @doc Create a genesis block with the mainnet genesis accounts.
init() ->
	init(ar_util:genesis_wallets()).

%% @doc Create a genesis block with the given accounts and difficulty=1.
init(WalletList) ->
	init(WalletList, 1).

%% @doc Create a genesis block with the given accounts, difficulty and reward_pool=0.
init(WalletList, Diff) ->
	init(WalletList, Diff, 0).

%% @doc Create a genesis block with the given accounts, difficulty, and reward pool.
init(WalletList, StartingDiff, RewardPool) ->
	init(WalletList, StartingDiff, RewardPool, []).

%% @doc Create a genesis block with the given accounts, difficulty, reward pool,
%% and transactions.
init(WalletList, StartingDiff, RewardPool, TXs) ->
	WL = ar_patricia_tree:from_proplist([{A, {B, LTX}} || {A, B, LTX} <- WalletList]),
	WLH = element(1, ar_block:hash_wallet_list(0, unclaimed, WL)),
	case WalletList of
		[] ->
			ok;
		_ ->
			ok = ar_storage:write_wallet_list(WLH, WL)
	end,
	SizeTaggedTXs = ar_block:generate_size_tagged_list_from_txs(TXs, 0),
	BlockSize = case SizeTaggedTXs of [] -> 0; _ -> element(2, lists:last(SizeTaggedTXs)) end,
	SizeTaggedDataRoots = [{Root, Offset} || {{_, Root}, Offset} <- SizeTaggedTXs],
	{TXRoot, _Tree} = ar_merkle:generate_tree(SizeTaggedDataRoots),
	Timestamp = os:system_time(second),
	B0 =
		#block{
			txs = TXs,
			tx_root = TXRoot,
			wallet_list = WLH,
			diff = StartingDiff,
			cumulative_diff = ar_difficulty:next_cumulative_diff(0, StartingDiff, 0),
			weave_size = BlockSize,
			block_size = BlockSize,
			reward_pool = RewardPool,
			timestamp = Timestamp,
			last_retarget = Timestamp,
			size_tagged_txs = SizeTaggedTXs,
			usd_to_ar_rate = ?NEW_WEAVE_USD_TO_AR_RATE,
			scheduled_usd_to_ar_rate = ?NEW_WEAVE_USD_TO_AR_RATE,
			packing_2_5_threshold = 0,
			strict_data_split_threshold = BlockSize
		},
	B1 =
		case ar_fork:height_2_6() > 0 of
			true ->
				B0;
			false ->
				B0#block{ packing_2_6_threshold = BlockSize }
		end,
	B2 =
		case ar_block:is_2_6_repacking_complete(B1) of
			true ->
				B1#block{ nonce = 0 };
			false ->
				B1#block{ nonce = <<>> }
		end,
	[B2#block{ indep_hash = ar_block:indep_hash(B2) }].

read_v1_genesis_txs() ->
	{ok, Files} = file:list_dir("data/genesis_txs"),
	{ok, Config} = application:get_env(arweave, config),
	lists:foldl(
		fun(F, Acc) ->
			file:copy(
				"data/genesis_txs/" ++ F,
				Config#config.data_dir ++ "/" ++ ?TX_DIR ++ "/" ++ F
			),
			[ar_util:decode(hd(string:split(F, ".")))|Acc]
		end,
		[],
		Files
	).

%% @doc Return the mainnet genesis transactions.
create_genesis_txs() ->
	TXs = lists:map(
		fun({M}) ->
			{Priv, Pub} = ar_wallet:new(),
			LastTx = <<>>,
			Data = unicode:characters_to_binary(M),
			TX = ar_tx:new(Data, 0, LastTx),
			Reward = 0,
			SignedTX = ar_tx:sign_v1(TX#tx{reward = Reward}, Priv, Pub),
			ar_storage:write_tx(SignedTX),
			SignedTX
		end,
		?GENESIS_BLOCK_MESSAGES
	),
	ar_storage:write_file_atomic(
		"genesis_wallets.csv",
		lists:map(fun(T) -> binary_to_list(ar_util:encode(T#tx.id)) ++ "," end, TXs)
	),
	[T#tx.id || T <- TXs].
