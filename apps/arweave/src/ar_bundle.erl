%%% @doc The module contains bundle serialisation/deserialisation functions.
-module(ar_bundle).

%% to use: in this folder, type:
%% $ erl
%% 1> c(ar_bundle).
%% {ok,ar_bundle}
%% 2> ar_bundle:parse_ans104_header(<< 1:32, 78:32, -1:256 >>).

-record(ans104_item, {
	sigtype, signature, owner,
	target = <<>>,
	anchor = <<>>,
	tag_count = 0, tags = <<>>
}).

-export([parse_ans104_header/1, parse_ans104_dataitem_header/1]).

parse_ans104_header(<< Count:32, Rest/binary >>) when Count =< 100000000 ->
	parse_ans104_header(Count, Rest, 32 + Count * 64, []);
parse_ans104_header(_Bin) ->
	{error, invalid_ans104_header}.

parse_ans104_header(0, << Rest/binary >>, _Offset, Entries) ->
	{ok, Entries, Rest};
parse_ans104_header(N, << Size:32, ID:32/binary, Rest/binary >>, Offset, Entries) 
		when  N > 0 ->
	parse_ans104_header(N - 1, Rest, Offset + Size, [Entries | {Offset, Size, ID}]);
parse_ans104_header(_N, _Bin, _Offset, _Entries) ->
	{error, invalid_ans104_header}.

parse_ans104_dataitem_header(
		<< 1:16, SigRSA:512/binary, OwnerRSA:512/binary, Rest/binary >>) ->
	parse_ans104_dataitem_target(Rest, #ans104_item{
			sigtype = 1, signature = SigRSA, owner = OwnerRSA
	});
parse_ans104_dataitem_header(
		<< 2:16, SigCurve25519:64/binary, OwnerCurve25519:32/binary, Rest/binary >>) ->
	parse_ans104_dataitem_target(Rest, #ans104_item{
			sigtype = 2, signature = SigCurve25519, owner = OwnerCurve25519
	});
parse_ans104_dataitem_header(
		<< 3:16, SigSecp256k1:65/binary, OwnerSecp256k1:65/binary, Rest/binary >>) ->
	parse_ans104_dataitem_target(Rest, #ans104_item{
			sigtype = 3, signature = SigSecp256k1, owner = OwnerSecp256k1
	});
parse_ans104_dataitem_header(
		<< 4:16, SigSolana:64/binary, OwnerSolana:32/binary, Rest/binary >>) ->
	parse_ans104_dataitem_target(Rest, #ans104_item{
			sigtype = 4, signature = SigSolana, owner = OwnerSolana
	});
parse_ans104_dataitem_header(_Bin) ->
	{error, invalid_ans104_dataitem_header}.

parse_ans104_dataitem_target(<< 1:8, Target:32/binary, Rest/binary >>, DI) ->
	parse_ans104_dataitem_anchor(Rest, DI#ans104_item{
	       target = Target
	});
parse_ans104_dataitem_target(<< 0:8, Rest/binary >>, DI) ->
	parse_ans104_dataitem_anchor(Rest, DI#ans104_item{
	       target = <<>>
	});
parse_ans104_dataitem_target(_Bin, _DI) ->
	{error, invalid_ans104_dataitem_header}.

parse_ans104_dataitem_anchor(<< 1:8, Anchor:32/binary, Rest/binary >>, DI) ->
	parse_ans104_dataitem_tags(Rest, DI#ans104_item{
	       anchor = Anchor
	});
parse_ans104_dataitem_anchor(<< 0:8, Rest/binary >>, DI) ->
	parse_ans104_dataitem_tags(Rest, DI#ans104_item{
	       anchor = <<>>
	});
parse_ans104_dataitem_anchor(_Bin, _DI) ->
	{error, invalid_ans104_dataitem_header}.

parse_ans104_dataitem_tags(<< Count:64, Size:64, AvroData:Size/binary, _Rest/binary >>, DI) ->
%	% avro parsing maybe goes here.  can use a library, or manually parse this simple structure.
	{ok, DI#ans104_item{
	       tag_count = Count,
	       tags = AvroData
	}}.
