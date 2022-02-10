-module(ar_poller_worker).

-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include_lib("arweave/include/ar.hrl").
-include_lib("arweave/include/ar_config.hrl").

-record(state, {
	peer,
	polling_frequency_ms,
	pause = false
}).

%%%===================================================================
%%% Public interface.
%%%===================================================================

start_link(Name) ->
	gen_server:start_link({local, Name}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks.
%%%===================================================================

init([]) ->
	process_flag(trap_exit, true),
	{ok, Config} = application:get_env(arweave, config),
	[ok] = ar_events:subscribe([node_state]),
	{ok, #state{ polling_frequency_ms = Config#config.polling * 1000 }}.

handle_call(Request, _From, State) ->
	?LOG_WARNING("event: unhandled_call, request: ~p", [Request]),
	{reply, ok, State}.

handle_cast(poll, #state{ peer = undefined } = State) ->
	ar_util:cast_after(1000, self(), poll),
	{noreply, State};
handle_cast(poll, #state{ peer = Peer, polling_frequency_ms = FrequencyMs } = State) ->
	case ar_http_iface_client:get_recent_hash_list(Peer) of
		{ok, HL} ->
			case get_earliest_unknown_block(HL, not_set) of
				match ->
					ok;
				not_found ->
					?LOG_WARNING([{event, peer_stuck_or_deviated},
							{peer, ar_util:format_peer(Peer)},
							{base_h, ar_util:encode(lists:last(HL))}]);
				H ->
					case ar_http_iface_client:get_block_shadow([Peer], H) of
						{Peer, B, Time, Size} ->
							ar_events:send(block, {discovered, Peer, B, Time, Size});
						_ ->
							ok
					end
			end,
			ar_util:cast_after(FrequencyMs, self(), poll),
			{noreply, State};
		{error, request_type_not_found} ->
			{noreply, State#state{ pause = true }};
		Error ->
			?LOG_DEBUG([{event, failed_to_fetch_block},
					{peer, ar_util:format_peer(Peer)}, {error, io_lib:format("~p", [Error])}]),
			{noreply, State#state{ pause = true }}
	end;

handle_cast({set_peer, Peer}, #state{ pause = Pause } = State) ->
	case Pause of
		true ->
			gen_server:cast(self(), poll);
		false ->
			ok
	end,
	{noreply, State#state{ peer = Peer, pause = false }};

handle_cast(Msg, State) ->
	?LOG_ERROR([{event, unhandled_cast}, {module, ?MODULE}, {message, Msg}]),
	{noreply, State}.

handle_info({event, node_state, initialized}, State) ->
	gen_server:cast(self(), poll),
	{noreply, State};

handle_info({event, node_state, _}, State) ->
	{noreply, State};

handle_info({gun_down, _, http, normal, _, _}, State) ->
	{noreply, State};
handle_info({gun_down, _, http, closed, _, _}, State) ->
	{noreply, State};
handle_info({gun_up, _, http}, State) ->
	{noreply, State};

handle_info(Info, State) ->
	?LOG_ERROR([{event, unhandled_info}, {module, ?MODULE}, {info, Info}]),
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

%%%===================================================================
%%% Private functions.
%%%===================================================================

get_earliest_unknown_block([H | HL], PrevH) ->
	case ar_block_cache:get(block_cache, H) of
		not_found ->
			get_earliest_unknown_block(HL, H);
		#block{} ->
			case PrevH of
				not_set ->
					%% We already have all peer's recent blocks in the cache.
					match;
				_ ->
					PrevH
			end
	end;
get_earliest_unknown_block([], _) ->
	not_found.
