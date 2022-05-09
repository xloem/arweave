-module(ar_block_pre_validator).

-behaviour(gen_server).

-export([start_link/2, pre_validate/5]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include_lib("arweave/include/ar.hrl").
-include_lib("arweave/include/ar_consensus.hrl").

-record(state, {
	%% The priority queue storing the validation requests.
	pqueue = gb_sets:new(),
	%% The total size in bytes of the priority queue.
	size = 0,
	%% The map IP => the timestamp of the last block from this IP.
	ip_timestamps = #{},
	%% The map SolutionHash => the timestamp of the last block with this solution hash.
	hash_timestamps = #{}
}).

%% The maximum size in bytes the blocks enqueued for pre-validation can occupy.
-define(MAX_PRE_VALIDATION_QUEUE_SIZE, (200 * 1024 * 1024)).

%% Accept a block from the given IP only once in so many milliseconds.
-define(THROTTLE_BY_IP_INTERVAL_MS, 1000).

%% Accept a block with the given solution hash only once in so many milliseconds.
-define(THROTTLE_BY_SOLUTION_HASH_INTERVAL_MS, 2000).

%%%===================================================================
%%% Public interface.
%%%===================================================================

start_link(Name, Workers) ->
	gen_server:start_link({local, Name}, ?MODULE, Workers, []).

%% @doc Partially validate the received block. The validation consists of multiple
%% stages. The process is aiming to increase resistance against DDoS attacks.
%% The first stage is the quickest and performed synchronously when this function
%% is called. Afterwards, the block is put in a limited-size priority queue.
%% Bigger-height blocks from better-rated peers have higher priority. Additionally,
%% the processing is throttled by IP and solution hash.
pre_validate(B, Peer, Timestamp, ReadBodyTime, BodySize) ->
	#block{ indep_hash = H } = B,
	case ar_ignore_registry:member(H) of
		true ->
			ok;
		false ->
			pre_validate_is_peer_banned(B, Peer, Timestamp, ReadBodyTime, BodySize)
	end.

%%%===================================================================
%%% gen_server callbacks.
%%%===================================================================

init([]) ->
	process_flag(trap_exit, true),
	gen_server:cast(?MODULE, pre_validate),
	ok = ar_events:subscribe(block),
	{ok, #state{}}.

handle_cast(pre_validate, #state{ pqueue = Q, size = Size, ip_timestamps = IPTimestamps,
			hash_timestamps = HashTimestamps } = State) ->
	case gb_sets:is_empty(Q) of
		true ->
			ar_util:cast_after(50, ?MODULE, pre_validate),
			{noreply, State};
		false ->
			{{_, {B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize}},
					Q2} = gb_sets:take_largest(Q),
			Size2 = Size - BodySize,
			ThrottleByIPResult = throttle_by_ip(Peer, IPTimestamps),
			{IPTimestamps3, HashTimestamps3} =
				case ThrottleByIPResult of
					false ->
						{IPTimestamps, HashTimestamps};
					{true, IPTimestamps2} ->
						case throttle_by_solution_hash(B#block.hash, HashTimestamps) of
							{true, HashTimestamps2} ->
								pre_validate_pow_or_search_space_number(B, BDS, PrevB, Peer,
										Timestamp, ReadBodyTime, BodySize),
								{IPTimestamps2, HashTimestamps2};
							false ->
								{IPTimestamps2, HashTimestamps}
						end
				end,
			gen_server:cast(?MODULE, pre_validate),
			{noreply, State#state{ pqueue = Q2, size = Size2, ip_timestamps = IPTimestamps3,
					hash_timestamps = HashTimestamps3 }}
	end;

handle_cast({enqueue, {B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize}}, State) ->
	#state{ pqueue = Q, size = Size } = State,
	Priority = priority(B, Peer),
	Size2 = Size + BodySize,
	Q2 = gb_sets:add_element({Priority, {B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
			BodySize}}, Q),
	{Q3, Size3} =
		case Size2 > ?MAX_PRE_VALIDATION_QUEUE_SIZE of
			true ->
				drop_tail(Q2, Size2);
			false ->
				{Q2, Size2}
		end,
	{noreply, State#state{ pqueue = Q3, size = Size3 }};

handle_cast({may_be_remove_ip_timestamp, IP}, #state{ ip_timestamps = Timestamps } = State) ->
	Now = os:system_time(millisecond),
	case maps:get(IP, Timestamps, not_set) of
		not_set ->
			{noreply, State};
		Timestamp when Timestamp < Now - ?THROTTLE_BY_IP_INTERVAL_MS ->
			{noreply, State#state{ ip_timestamps = maps:remove(IP, Timestamps) }};
		_ ->
			{noreply, State}
	end;

handle_cast({may_be_remove_h_timestamp, H}, #state{ hash_timestamps = Timestamps } = State) ->
	Now = os:system_time(millisecond),
	case maps:get(H, Timestamps, not_set) of
		not_set ->
			{noreply, State};
		Timestamp when Timestamp < Now - ?THROTTLE_BY_SOLUTION_HASH_INTERVAL_MS ->
			{noreply, State#state{ hash_timestamps = maps:remove(H, Timestamps) }};
		_ ->
			{noreply, State}
	end;

handle_cast(Msg, State) ->
	?LOG_ERROR([{event, unhandled_cast}, {module, ?MODULE}, {message, Msg}]),
	{noreply, State}.

handle_call(Request, _From, State) ->
	?LOG_WARNING("event: unhandled_call, request: ~p", [Request]),
	{reply, ok, State}.

handle_info({event, block, {mined, #block{ indep_hash = H }, _TXs, _CurrentBH}}, State) ->
	ar_ignore_registry:add(H),
	{noreply, State};

handle_info({event, block, _}, State) ->
	{noreply, State};

handle_info(Info, State) ->
	?LOG_ERROR([{event, unhandled_info}, {module, ?MODULE}, {info, Info}]),
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

%%%===================================================================
%%% Private functions.
%%%===================================================================

pre_validate_is_peer_banned(B, Peer, Timestamp, ReadBodyTime, BodySize) ->
	case ar_blacklist_middleware:is_peer_banned(Peer) of
		not_banned ->
			pre_validate_previous_block(B, Peer, Timestamp, ReadBodyTime, BodySize);
		banned ->
			ok
	end.

pre_validate_previous_block(B, Peer, Timestamp, ReadBodyTime, BodySize) ->
	PrevH = B#block.previous_block,
	case ar_node:get_block_shadow_from_cache(PrevH) of
		not_found ->
			%% We have not seen the previous block yet - might happen if two
			%% successive blocks are distributed at the same time. Do not
			%% ban the peer as the block might be valid. If the network adopts
			%% this block, ar_poller will catch up.
			ok;
		#block{ height = PrevHeight } = PrevB ->
			case B#block.height == PrevHeight + 1 of
				false ->
					ok;
				true ->
					case B#block.height >= ar_fork:height_2_6() of
						true ->
							pre_validate_indep_hash(B, PrevB, Peer, Timestamp, ReadBodyTime,
									BodySize);
						false ->
							pre_validate_may_be_fetch_chunk(B, none, PrevB, Peer, Timestamp,
									ReadBodyTime, BodySize)
					end
			end
	end.

pre_validate_indep_hash(#block{ indep_hash = H } = B, PrevB, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	case catch compute_hash(B) of
		{ok, {BDS, H}} ->
			ar_ignore_registry:add_temporary(H, 5000),
			pre_validate_timestamp(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize);
		{ok, H} ->
			ar_ignore_registry:add_temporary(H, 5000),
			pre_validate_timestamp(B, none, PrevB, Peer, Timestamp, ReadBodyTime, BodySize);
		{error, invalid_signature} ->
			post_block_reject_warn(B, check_signature, Peer),
			ar_events:send(block, {rejected, invalid_signature, B#block.hash, Peer}),
			ok;
		_ ->
			post_block_reject_warn(B, check_indep_hash, Peer),
			ar_events:send(block, {rejected, invalid_hash, B#block.indep_hash, Peer}),
			ok
	end.

pre_validate_timestamp(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	#block{ indep_hash = H } = B,
	case ar_block:verify_timestamp(B, PrevB) of
		false ->
			%% If it is too early and nobody will re-send the block,
			%% ar_poller will fetch it later.
			post_block_reject_warn(B, check_timestamp, Peer, [{block_time, B#block.timestamp},
					{current_time, os:system_time(seconds)}]),
			ar_events:send(block, {rejected, invalid_timestamp, H, Peer}),
			ar_ignore_registry:remove_temporary(B#block.indep_hash),
			ok;
		true ->
			pre_validate_previous_solution_hash(B, BDS, PrevB, Peer, Timestamp,
					ReadBodyTime, BodySize)
	end.

pre_validate_previous_solution_hash(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	case ar_block:is_2_6_repacking_complete(B) of
		false ->
			pre_validate_last_retarget(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
					BodySize);
		true ->
			case B#block.previous_solution_hash == PrevB#block.hash of
				false ->
					post_block_reject_warn(B, check_previous_solution_hash, Peer),
					ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
					ar_events:send(block, {rejected, invalid_previous_solution_hash,
							B#block.indep_hash, Peer}),
					ok;
				true ->
					pre_validate_last_retarget(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
							BodySize)
			end
	end.

pre_validate_last_retarget(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	case B#block.height >= ar_fork:height_2_6() of
		false ->
			pre_validate_difficulty(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize);
		true ->
			case ar_block:verify_last_retarget(B, PrevB) of
				true ->
					pre_validate_difficulty(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
									BodySize);
				false ->
					post_block_reject_warn(B, check_last_retarget, Peer),
					ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
					ar_events:send(block, {rejected, invalid_last_retarget,
							B#block.indep_hash, Peer}),
					ok
			end
	end.

pre_validate_difficulty(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	ExpectedDiff =
		case B#block.height >= ar_fork:height_2_6() of
			true ->
				ar_retarget:maybe_retarget(B#block.height, PrevB#block.diff,
						B#block.timestamp, PrevB#block.last_retarget, PrevB#block.timestamp);
			false ->
				ar_mine:min_difficulty(B#block.height)
		end,
	case B#block.diff >= ExpectedDiff of
		true ->
			case B#block.height >= ar_fork:height_2_6() of
				true ->
					pre_validate_quick_pow(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
							BodySize);
				false ->
					pre_validate_pow(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize)
			end;
		_ ->
			post_block_reject_warn(B, check_difficulty, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_difficulty, B#block.indep_hash, Peer}),
			ok
	end.

pre_validate_quick_pow(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	#block{ previous_block = PrevH, hash_preimage = HashPreimage, diff = Diff,
			nonce_limiter_info = NonceLimiterInfo,
			search_space_number = SearchSpaceNumber, reward_addr = RewardAddr } = B,
	SolutionHash =
		case ar_block:is_2_6_repacking_complete(B) of
			false ->
				crypto:hash(sha256, << PrevH/binary, HashPreimage/binary >>);
			true ->
				NonceLimiterOutput = hd(NonceLimiterInfo#nonce_limiter_info.checkpoints),
				H0 = ar_block:compute_h0(NonceLimiterOutput, SearchSpaceNumber,
						PrevB#block.hash, RewardAddr),
				crypto:hash(sha256, << H0/binary, HashPreimage/binary >>)
		end,
	case binary:decode_unsigned(SolutionHash, big) > Diff of
		false ->
			post_block_reject_warn(B, check_hash_preimage, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_hash_preimage, B#block.indep_hash, Peer}),
			ok;
		true ->
			gen_server:cast(?MODULE, {enqueue, {B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
					BodySize}})
	end.

pre_validate_pow_or_search_space_number(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	case ar_block:is_2_6_repacking_complete(B) of
		false ->
			pre_validate_may_be_fetch_chunk(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
					BodySize);
		true ->
			pre_validate_search_space_number(B, PrevB, Peer, Timestamp, ReadBodyTime,
					BodySize)
	end.

pre_validate_search_space_number(B, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	PrevH = PrevB#block.indep_hash,
	case ar_node:get_recent_search_space_upper_bound_by_prev_h(PrevH) of
		not_found ->
			%% The new blocks should have been applied in the meantime since we
			%% looked for the previous block in the block cache.
			ok;
		SearchSpaceUpperBound ->
			Max = max(0, SearchSpaceUpperBound div ?SEARCH_SPACE_SIZE - 1),
			case B#block.search_space_number > Max of
				true ->
					post_block_reject_warn(B, check_search_space_number, Peer),
					ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
					ar_events:send(block, {rejected, invalid_search_space_number,
							B#block.indep_hash, Peer}),
					ok;
				false ->
					pre_validate_nonce(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
							ReadBodyTime, BodySize)
			end
	end.

pre_validate_nonce(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	Max = max(0, ?RECALL_SUBSPACE_SIZE div ?DATA_CHUNK_SIZE - 1),
	case B#block.nonce > Max of
		true ->
			post_block_reject_warn(B, check_nonce, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_nonce, B#block.indep_hash, Peer}),
			ok;
		false ->
			pre_validate_may_be_fetch_first_chunk(B, PrevB, SearchSpaceUpperBound, Peer,
					Timestamp, ReadBodyTime, BodySize)
	end.

pre_validate_may_be_fetch_first_chunk(#block{ recall_byte = RecallByte,
		poa = #poa{ chunk = <<>> } } = B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
		ReadBodyTime, BodySize) when RecallByte /= undefined ->
	case ar_data_sync:get_chunk(RecallByte + 1, #{ pack => true,
			packing => {spora_2_6, B#block.reward_addr}, bucket_based_offset => true }) of
		{ok, #{ chunk := Chunk, data_path := DataPath, tx_path := TXPath }} ->
			prometheus_counter:inc(block2_fetched_chunks),
			B2 = B#block{ poa = #poa{ chunk = Chunk, data_path = DataPath,
					tx_path = TXPath } },
			pre_validate_may_be_fetch_second_chunk(B2, PrevB, SearchSpaceUpperBound, Peer,
					Timestamp, ReadBodyTime, BodySize);
		_ ->
			ar_events:send(block, {rejected, failed_to_fetch_first_chunk, B#block.indep_hash,
					Peer}),
			ok
	end;
pre_validate_may_be_fetch_first_chunk(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
		ReadBodyTime, BodySize) ->
	pre_validate_may_be_fetch_second_chunk(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
			ReadBodyTime, BodySize).

pre_validate_may_be_fetch_second_chunk(#block{ recall_byte2 = RecallByte2,
		poa2 = #poa{ chunk = <<>> } } = B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
		ReadBodyTime, BodySize) when RecallByte2 /= undefined ->
	case ar_data_sync:get_chunk(RecallByte2 + 1, #{ pack => true,
			packing => {spora_2_6, B#block.reward_addr}, bucket_based_offset => true }) of
		{ok, #{ chunk := Chunk, data_path := DataPath, tx_path := TXPath }} ->
			prometheus_counter:inc(block2_fetched_chunks),
			B2 = B#block{ poa2 = #poa{ chunk = Chunk, data_path = DataPath,
					tx_path = TXPath } },
			pre_validate_pow_2_7(B2, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
					ReadBodyTime, BodySize);
		_ ->
			ar_events:send(block, {rejected, failed_to_fetch_second_chunk, B#block.indep_hash,
					Peer}),
			ok
	end;
pre_validate_may_be_fetch_second_chunk(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp,
			ReadBodyTime, BodySize) ->
	pre_validate_pow_2_7(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp, ReadBodyTime,
			BodySize).

pre_validate_pow_2_7(B, PrevB, SearchSpaceUpperBound, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	NonceLimiterOutput = hd((B#block.nonce_limiter_info)#nonce_limiter_info.checkpoints),
	H0 = ar_block:compute_h0(NonceLimiterOutput, B#block.search_space_number,
			PrevB#block.hash, B#block.reward_addr),
	Chunk1 = (B#block.poa)#poa.chunk,
	{H1, Preimage1} = ar_block:compute_h1(H0, B#block.nonce, Chunk1),
	case H1 == B#block.hash andalso binary:decode_unsigned(H1, big) > B#block.diff
			andalso Preimage1 == B#block.hash_preimage
			andalso B#block.recall_byte2 == undefined of
		true ->
			pre_validate_poa(B, SearchSpaceUpperBound, H0, H1, Peer, Timestamp, ReadBodyTime,
					BodySize);
		false ->
			Chunk2 = (B#block.poa2)#poa.chunk,
			{H2, Preimage2} = ar_block:compute_h2(H1, Chunk2),
			case H2 == B#block.hash andalso binary:decode_unsigned(H2, big) > B#block.diff
					andalso Preimage2 == B#block.hash_preimage of
				true ->
					pre_validate_poa(B, SearchSpaceUpperBound, H0, H1, Peer, Timestamp,
							ReadBodyTime, BodySize);
				false ->
					post_block_reject_warn(B, check_pow, Peer),
					ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
					ar_events:send(block, {rejected, invalid_pow, B#block.indep_hash, Peer}),
					ok
			end
	end.

pre_validate_poa(B, SearchSpaceUpperBound, H0, H1, Peer, Timestamp, ReadBodyTime,
		BodySize) ->
	{RecallSubspace1Start, RecallSubspace2Start} = ar_block:get_recall_space(H0,
			B#block.search_space_number, SearchSpaceUpperBound),
	RecallByte1 = RecallSubspace1Start + B#block.nonce * ?DATA_CHUNK_SIZE,
	{BlockStart1, BlockEnd1, TXRoot1} = ar_block_index:get_block_bounds(RecallByte1),
	BlockSize1 = BlockEnd1 - BlockStart1,
	case ar_poa:validate(BlockStart1, RecallByte1, TXRoot1, BlockSize1, B#block.poa, 0,
			?STRICT_DATA_SPLIT_THRESHOLD, B#block.reward_addr)
				andalso RecallByte1 == B#block.recall_byte of
		false ->
			post_block_reject_warn(B, check_poa, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_poa, B#block.indep_hash, Peer}),
			ok;
		true ->
			case B#block.hash == H1 of
				true ->
					pre_validate_nonce_limiter(B, Peer, Timestamp, ReadBodyTime, BodySize);
				false ->
					RecallByte2 = RecallSubspace2Start + B#block.nonce * ?DATA_CHUNK_SIZE,
					{BlockStart2, BlockEnd2, TXRoot2} = ar_block_index:get_block_bounds(
							RecallByte2),
					BlockSize2 = BlockEnd2 - BlockStart2,
					case ar_poa:validate(BlockStart2, RecallByte2, TXRoot2, BlockSize2,
							B#block.poa2, 0, ?STRICT_DATA_SPLIT_THRESHOLD,
							B#block.reward_addr)
								andalso RecallByte2 == B#block.recall_byte2 of
						false ->
							post_block_reject_warn(B, check_poa2, Peer),
							ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
							ar_events:send(block, {rejected, invalid_poa2,
									B#block.indep_hash, Peer}),
							ok;
						true ->
							pre_validate_nonce_limiter(B, Peer, Timestamp, ReadBodyTime,
									BodySize)
					end
			end
	end.

pre_validate_nonce_limiter(B, Peer, Timestamp, ReadBodyTime, BodySize) ->
	case ar_nonce_limiter:pre_validate(B) of
		false ->
			post_block_reject_warn(B, check_nonce_limiter, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_nonce_limiter, B#block.indep_hash, Peer}),
			ok;
		true ->
			ar_ignore_registry:add(B#block.indep_hash),
			ar_events:send(block, {new, B, Peer}),
			ar_events:send(peer, {gossiped_block, Peer, ReadBodyTime, BodySize}),
			record_block_pre_validation_time(Timestamp),
			?LOG_INFO([{event, ar_http_iface_handler_accepted_block},
					{indep_hash, ar_util:encode(B#block.indep_hash)}]),
			ok
	end.

pre_validate_may_be_fetch_chunk(#block{ recall_byte = RecallByte,
		poa = #poa{ chunk = <<>> } } = B, BDS, PrevB, Peer, Timestamp, ReadBodyTime,
		BodySize) when RecallByte /= undefined ->
	case ar_node:get_recent_search_space_upper_bound_by_prev_h(PrevB#block.indep_hash) of
		not_found ->
			%% The new blocks should have been applied in the meantime since we
			%% looked for the previous block in the block cache.
			ok;
		SearchSpaceUpperBound ->
			Options =
				case B#block.height >= ar_fork:height_2_6() of
					true ->
						Packing_2_6_Threshold =
							case B#block.height == ar_fork:height_2_6() of
								true ->
									SearchSpaceUpperBound;
								false ->
									ar_block:shift_packing_2_6_threshold(
											PrevB#block.packing_2_6_threshold)
							end,
						Packing =
							case RecallByte >= Packing_2_6_Threshold of
								true ->
									{spora_2_6, B#block.reward_addr};
								false ->
									spora_2_5
							end,
						#{ pack => true, packing => Packing, bucket_based_offset => true };
					false ->
						#{ pack => false, packing => spora_2_5, bucket_based_offset => true }
				end,
			case ar_data_sync:get_chunk(RecallByte + 1, Options) of
				{ok, #{ chunk := Chunk, data_path := DataPath, tx_path := TXPath }} ->
					prometheus_counter:inc(block2_fetched_chunks),
					B2 = B#block{ poa = #poa{ chunk = Chunk, tx_path = TXPath,
							data_path = DataPath } },
					pre_validate_pow_or_indep_hash(B2, BDS, PrevB, Peer, Timestamp,
							ReadBodyTime, BodySize);
				_ ->
					ar_events:send(block, {rejected, failed_to_fetch_chunk, B#block.indep_hash,
							Peer}),
					ok
			end
	end;
pre_validate_may_be_fetch_chunk(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	pre_validate_pow_or_indep_hash(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize).

pre_validate_pow_or_indep_hash(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	case B#block.height >= ar_fork:height_2_6() of
		true ->
			pre_validate_pow(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize);
		false ->
			pre_validate_indep_hash(B, PrevB, Peer, Timestamp, ReadBodyTime, BodySize)
	end.

pre_validate_pow(B, BDS, PrevB, Peer, Timestamp, ReadBodyTime, BodySize) ->
	#block{ indep_hash = PrevH } = PrevB,
	MaybeValid =
		case ar_node:get_recent_search_space_upper_bound_by_prev_h(PrevH) of
			not_found ->
				not_found;
			SearchSpaceUpperBound ->
				validate_spora_pow(B, PrevB, BDS, SearchSpaceUpperBound)
		end,
	case MaybeValid of
		not_found ->
			%% The new blocks should have been applied in the meantime since we
			%% looked for the previous block in the block cache.
			ok;
		{true, RecallByte} ->
			case B#block.height < ar_fork:height_2_6()
					orelse RecallByte == B#block.recall_byte of
				false ->
					post_block_reject_warn(B, invalid_recall_byte, Peer),
					ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
					ar_events:send(block, {rejected, invalid_recall_byte, B#block.indep_hash,
							Peer});
				true ->
					H = B#block.indep_hash,
					ar_ignore_registry:add(H),
					%% Include all transactions found in the mempool in place of the
					%% corresponding transaction identifiers so that we can gossip them to
					%% peers who miss them along with the block.
					B2 = B#block{ txs = include_transactions(B#block.txs) },
					ar_events:send(block, {new, B2, #{ source => {peer, Peer},
							recall_byte => RecallByte }}),
					ar_events:send(peer, {gossiped_block, Peer, ReadBodyTime, BodySize}),
					record_block_pre_validation_time(Timestamp),
					prometheus_counter:inc(block2_received_transactions,
							count_received_transactions(B#block.txs)),
					?LOG_INFO([{event, accepted_block}, {indep_hash, ar_util:encode(H)}]),
					ok
			end;
		false ->
			post_block_reject_warn(B, check_pow, Peer),
			ar_blacklist_middleware:ban_peer(Peer, ?BAD_BLOCK_BAN_TIME),
			ar_events:send(block, {rejected, invalid_pow, B#block.indep_hash, Peer}),
			ok
	end.

compute_hash(B) ->
	case ar_block:is_2_6_repacking_complete(B) of
		false ->
			BDS = ar_block:generate_block_data_segment(B),
			{ok, {BDS, ar_block:indep_hash(BDS, B)}};
		true ->
			SignedH = ar_block:generate_signed_hash(B),
			case ar_block:verify_signature(SignedH, B) of
				false ->
					{error, invalid_signature};
				{true, SignedH} ->
					{ok, ar_block:indep_hash2(SignedH, B#block.signature)}
			end
	end.

include_transactions([#tx{} = TX | TXs]) ->
	[TX | include_transactions(TXs)];
include_transactions([]) ->
	[];
include_transactions([TXID | TXs]) ->
	case ets:lookup(node_state, {tx, TXID}) of
		[] ->
			[TXID | include_transactions(TXs)];
		[{_, TX}] ->
			[TX | include_transactions(TXs)]
	end.

count_received_transactions(TXs) ->
	count_received_transactions(TXs, 0).

count_received_transactions([#tx{} | TXs], N) ->
	count_received_transactions(TXs, N + 1);
count_received_transactions([_ | TXs], N) ->
	count_received_transactions(TXs, N);
count_received_transactions([], N) ->
	N.

post_block_reject_warn(B, Step, Peer) ->
	?LOG_WARNING([{event, post_block_rejected},
			{hash, ar_util:encode(B#block.indep_hash)}, {step, Step},
			{peer, ar_util:format_peer(Peer)}]).

post_block_reject_warn(B, Step, Peer, Params) ->
	?LOG_WARNING([{event, post_block_rejected},
			{hash, ar_util:encode(B#block.indep_hash)}, {step, Step},
			{params, Params}, {peer, ar_util:format_peer(Peer)}]).

validate_spora_pow(B, PrevB, BDS, SearchSpaceUpperBound) ->
	#block{ height = PrevHeight, indep_hash = PrevH } = PrevB,
	#block{ height = Height, nonce = Nonce, timestamp = Timestamp,
			poa = #poa{ chunk = Chunk } = SPoA } = B,
	Root = ar_block:compute_hash_list_merkle(PrevB),
	case {Root, PrevHeight + 1} == {B#block.hash_list_merkle, Height} of
		false ->
			false;
		true ->
			{H0, Entropy} = ar_mine:spora_h0_with_entropy(BDS, Nonce, Height),
			ComputeSolutionHash =
				case ar_mine:pick_recall_byte(H0, PrevH, SearchSpaceUpperBound) of
					{error, weave_size_too_small} ->
						case SPoA == #poa{} of
							false ->
								invalid_poa;
							true ->
								{ar_mine:spora_solution_hash(PrevH, Timestamp, H0, Chunk,
										Height), <<>>}
						end;
					{ok, Byte} ->
						{ar_mine:spora_solution_hash_with_entropy(PrevH, Timestamp, H0, Chunk,
								Entropy, Height), Byte}
				end,
			case ComputeSolutionHash of
				invalid_poa ->
					false;
				{{SolutionHash, HashPreimage}, RecallByte} ->
					case binary:decode_unsigned(SolutionHash, big) > B#block.diff
							andalso SolutionHash == B#block.hash
							andalso HashPreimage == B#block.hash_preimage of
						false ->
							false;
						true ->
							{true, RecallByte}
					end
			end
	end.

record_block_pre_validation_time(ReceiveTimestamp) ->
	TimeMs = timer:now_diff(erlang:timestamp(), ReceiveTimestamp) / 1000,
	prometheus_histogram:observe(block_pre_validation_time, TimeMs).

priority(B, Peer) ->
	{B#block.height, get_peer_score(Peer)}.

get_peer_score(Peer) ->
	get_peer_score(Peer, ar_peers:get_peers(), 0).

get_peer_score(Peer, [Peer | _Peers], N) ->
	N;
get_peer_score(Peer, [_Peer | Peers], N) ->
	get_peer_score(Peer, Peers, N - 1);
get_peer_score(_Peer, [], N) ->
	N - rand:uniform(100).

drop_tail(Q, Size) when Size =< ?MAX_PRE_VALIDATION_QUEUE_SIZE ->
	{Q, 0};
drop_tail(Q, Size) ->
	{{_Priority, {_, _, _, _, BodySize}}, Q2} = gb_sets:take_smallest(Q),
	drop_tail(Q2, Size - BodySize).

throttle_by_ip(Peer, Timestamps) ->
	IP = get_ip(Peer),
	Now = os:system_time(millisecond),
	ar_util:cast_after(?THROTTLE_BY_IP_INTERVAL_MS * 2, ?MODULE,
			{may_be_remove_ip_timestamp, IP}),
	case maps:get(IP, Timestamps, not_set) of
		not_set ->
			{true, maps:put(IP, Now, Timestamps)};
		Timestamp when Timestamp < Now - ?THROTTLE_BY_IP_INTERVAL_MS ->
			{true, maps:put(IP, Now, Timestamps)};
		_ ->
			false
	end.

get_ip({A, B, C, D, _Port}) ->
	{A, B, C, D}.

throttle_by_solution_hash(H, Timestamps) ->
	Now = os:system_time(millisecond),
	ar_util:cast_after(?THROTTLE_BY_SOLUTION_HASH_INTERVAL_MS * 2, ?MODULE,
			{may_be_remove_h_timestamp, H}),
	case maps:get(H, Timestamps, not_set) of
		not_set ->
			{true, maps:put(H, Now, Timestamps)};
		Timestamp when Timestamp < Now - ?THROTTLE_BY_SOLUTION_HASH_INTERVAL_MS ->
			{true, maps:put(H, Now, Timestamps)};
		_ ->
			false
	end.
