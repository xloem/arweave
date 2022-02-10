%% The number of RandomX hashes to compute to pack a chunk.
-define(PACKING_DIFFICULTY, 20).

%% The number of RandomX hashes to compute to pack a chunk after the fork 2.6.
-define(PACKING_DIFFICULTY_2_6, 30).

%% The size of the search space. The weave is broken down into search spaces
%% of equal size. A miner can search for a solution in each of the search spaces
%% in parallel, per mining address.
-ifdef(DEBUG).
-define(SEARCH_SPACE_SIZE, (4 * 1024 * 1024)).
-else.
-define(SEARCH_SPACE_SIZE, 4398046511104). % 4 * 1024 * 1024 * 1024 * 1024
-endif.

%% The size of a recall subspace. The first subspace is randomly chosen from the given
%% search space. The second subspace is chosen from the entire weave.
-ifdef(DEBUG).
-define(RECALL_SUBSPACE_SIZE, (100 * 1024)). % TODO function of height
-else.
-define(RECALL_SUBSPACE_SIZE, 104857600). % 100 * 1024 * 1024.
-endif.

%% The threshold was determined on the mainnet at the 2.5 fork block. The chunks
%% submitted after the threshold must adhere to stricter validation rules.
-define(STRICT_DATA_SPLIT_THRESHOLD, 30607159107830).

%% Recall bytes are only picked from the subspace up to the size
%% of the weave at the block of the depth defined by this constant.
-ifdef(DEBUG).
-define(SEARCH_SPACE_UPPER_BOUND_DEPTH, 3).
-else.
-define(SEARCH_SPACE_UPPER_BOUND_DEPTH, 50).
-endif.

%% The maximum mining difficulty. 2 ^ 256. The network difficulty
%% may theoretically be at most ?MAX_DIFF - 1.
-define(MAX_DIFF, (
	115792089237316195423570985008687907853269984665640564039457584007913129639936
)).

%%%===================================================================
%%% Pre-fork 2.7 constants.
%%%===================================================================

%% The size of the search space - a share of the weave randomly sampled
%% at every block. The solution must belong to the search space.
-define(SPORA_SEARCH_SPACE_SIZE(SearchSpaceUpperBound), fun() ->
	%% The divisor must be equal to SPORA_SEARCH_SPACE_SHARE
	%% defined in c_src/ar_mine_randomx.h.
	SearchSpaceUpperBound div 10 % 10% of the weave.
end()).

%% The number of contiguous subspaces of the search space, a roughly equal
%% share of the search space is sampled from each of the subspaces.
%% Must be equal to SPORA_SUBSPACES_COUNT defined in c_src/ar_mine_randomx.h.
-define(SPORA_SEARCH_SPACE_SUBSPACES_COUNT, 1024).

%% The minimum difficulty allowed.
-ifndef(SPORA_MIN_DIFFICULTY).
-define(SPORA_MIN_DIFFICULTY(Height), fun() ->
	Forks = {
		ar_fork:height_2_4()
	},
	case Forks of
		{Fork_2_4} when Height >= Fork_2_4 ->
			21
	end
end()).
-else.
-define(SPORA_MIN_DIFFICULTY(_Height), ?SPORA_MIN_DIFFICULTY).
-endif.
