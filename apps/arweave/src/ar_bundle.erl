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
	tags_count = 0,
	tags_avro = <<>>
}).

-export([parse_ans104_header/1, parse_ans104_dataitem_header/1, parse_ans104_tags_avro/1]).

%encode_ans104_header(Entries) 

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

%encode_vint(Value) when Value < 128 ->
%	<< Value:8 >>;
%encode_vint(Value) when Value >= 128 ->
%	<< 1:1, (Value band 127):7, (encode_vint(Value bsr 7))/binary >>.

parse_vint(<< 0:0, Value:7, Rest/binary >>) ->
	{ ok, Value, Rest };
parse_vint(<< 1:1, Value:7, Rest/binary >>) ->
	case parse_vint(Rest) of
		{error, Reason} ->
			{error, Reason};
		{ok, Significant, Bin} ->
			{ok, Value bor (Significant bsl 7), Bin}
	end;
parse_vint(_Bin) ->
	{error, invalid_vint}.

%encode_zigzag(TwosComplement) ->
%	Mid = TwosComplement bsl 1,
%	if Mid < 0 -> bnot Mid; true -> Mid end.

parse_zigzag(ZigZag) ->
	Mid = case ZigZag band 1 of 1 -> bnot ZigZag; 0 -> ZigZag end,
	Mid bsr 1.

%encode_avro_long(Long) ->
%	encode_vint(encode_zigzag(Long)).

parse_avro_long(Bin) ->
	case parse_vint(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, Value, Rest} ->
			{ok, parse_zigzag(Value), Rest}
	end.

%encode_avro_binary(<< Bin/binary >>) ->
%	<< (encode_vint(encode_zigzag(byte_size(Bin))))/binary, Bin >>.

parse_avro_bin(Bin) ->
	case parse_avro_long(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, Size, Bin2} when Size >= byte_size(Bin2) ->
			<< Bin3:Size/binary, Rest/binary >> = Bin2,
			{ok, Bin3, Rest};
		{ok, _Size, _Bin} ->
			{error, invalid_avro_bin}
	end.

parse_avro_array_block_header(Bin) ->
	case parse_avro_long(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, Count, Rest } when Count >= 0 ->
			{ok, Count, Rest};
		{ok, Count, Bin2} when Count < 0 ->
			case parse_avro_long(Bin2) of
				{error, Reason} ->
					{error, Reason};
				{ok, Size, Bin3} when Size >= byte_size(Bin3) ->
					<< Items:Size/binary, Rest/binary >> = Bin3,
					{ok, -Count, << Items, Rest >>};
				{ok, _Size, _Bin} ->
					{error, invalid_avro_array}
			end
	end.

parse_ans104_tag_avro(Bin) ->
	case parse_avro_bin(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, TagName, Rest} ->
			case parse_avro_bin(Rest) of
				{error, Reason} ->
					{error, Reason};
				{ok, TagValue, Rest} ->
					{ok, TagName, TagValue, Rest}
			end
	end.

parse_ans104_tags_avro_sequence(0, Rest, Tags) ->
	{ok, Tags, Rest};
parse_ans104_tags_avro_sequence(N, Bin, Tags) ->
	case parse_ans104_tag_avro(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, TagName, TagValue, Rest} ->
			parse_ans104_tags_avro_sequence(N - 1, Rest, [{TagName, TagValue} | Tags])
	end.
			
parse_ans104_tags_avro_blocks(Bin, PrevTags) ->
	case parse_avro_array_block_header(Bin) of
		{error, Reason} ->
			{error, Reason};
		{ok, 0, Rest} ->
			{ok, PrevTags, Rest};
		{ok, Count, Bin2} ->
			case parse_ans104_tags_avro_sequence(Count, Bin2, PrevTags) of
				{error, Reason} ->
					{error, Reason};
				{ok, BlockTags, Rest} ->
					parse_ans104_tags_avro_blocks(Rest, BlockTags)
			end
	end.

parse_ans104_tags_avro(Bin) ->
	parse_ans104_tags_avro_blocks(Bin, []).

parse_ans104_dataitem_tags(<< Count:64, Size:64, AvroData:Size/binary, Rest/binary >>, DI) ->
	{ok, DI#ans104_item{
		tags_count = Count,
		tags_avro = AvroData
	}, Rest}.
