%%% Copyright (C) 2009 Enrique Marcote, Miguel Rodriguez
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%
%%% o Redistributions of source code must retain the above copyright notice,
%%%   this list of conditions and the following disclaimer.
%%%
%%% o Redistributions in binary form must reproduce the above copyright notice,
%%%   this list of conditions and the following disclaimer in the documentation
%%%   and/or other materials provided with the distribution.
%%%
%%% o Neither the name of ERLANG TRAINING AND CONSULTING nor the names of its
%%%   contributors may be used to endorse or promote products derived from this
%%%   software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
%%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
%%% LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
%%% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
%%% SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
%%% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
%%% CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
%%% ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%%% POSSIBILITY OF SUCH DAMAGE.
-module(smpp_session).

%%% INCLUDE FILES
-include_lib("oserl/include/oserl.hrl").

%%% EXTERNAL EXPORTS
-export([congestion/3, connect/1, listen/1, tcp_send/2, send_pdu/3, controlling_process/2, close/1]).

%%% SOCKET LISTENER FUNCTIONS EXPORTS
-export([wait_accept/3, wait_recv/3, recv_loop/4]).

%% TIMER EXPORTS
-export([cancel_timer/1, start_timer/2]).

%%% MACROS
-define(CONNECT_OPTS(Ip),
        case Ip of
            undefined -> [binary, {packet, 0}, {active, false}];
            _         -> [binary, {packet, 0}, {active, false}, {ip, Ip}]
        end).
-define(CONNECT_TIME, 30000).
-define(LISTEN_OPTS(Ip),
        case Ip of
            undefined ->
              [binary, {packet, 0}, {active, false}, {reuseaddr, true}];
            _ ->
              [binary, {packet, 0}, {active, false}, {reuseaddr, true}, {ip, Ip}]
        end).

%%%-----------------------------------------------------------------------------
%%% EXTERNAL EXPORTS
%%%-----------------------------------------------------------------------------
%% Computes the congestion state.
%%
%% - CongestionSt: Current ``congestion_state`` value.
%% - WaitTime: Are the microseconds waiting for the PDU.
%% - Timestamp: Represents the moment when the PDU was received.
%%
%% The time since ``Timestamp`` is the PDU dispatching time.  If
%% this value equals the ``WaitTime`` (i.e. ``DispatchTime/WaitTime = 1``),
%% then we shall assume optimum load (value 85).  Having this in mind the
%% instant congestion state value is calculated.  Notice this value cannot be
%% greater than 99.
congestion(CongestionSt, WaitTime, Timestamp) ->
    case (timer:now_diff(?NOW, Timestamp) div (WaitTime + 1)) * 85 of
        Val when Val < 1 ->
            0;
        Val when Val > 99 ->  % Out of bounds
            ((19 * CongestionSt) + 99) div 20;
        Val ->
            ((19 * CongestionSt) + Val) div 20
    end.


connect(Opts) ->
    Ip = proplists:get_value(ip, Opts),
    UseSSL = proplists:get_value(ssl, Opts, false),
    case proplists:get_value(sock, Opts, undefined) of
        undefined ->
            Addr = proplists:get_value(addr, Opts),
            Port = proplists:get_value(port, Opts, ?DEFAULT_SMPP_PORT),
            connect(Addr, Port, ?CONNECT_OPTS(Ip), ?CONNECT_TIME, UseSSL);
        Sock ->
            case inet:setopts(Sock, ?CONNECT_OPTS(Ip)) of
                ok    -> {ok, Sock};
                Error -> Error
            end
    end.


connect(Addr, Port, ConnectOpts, ConnectTime, false) ->
    gen_tcp:connect(Addr, Port, ConnectOpts, ConnectTime);


connect(Addr, Port, ConnectOpts, ConnectTime, true) ->
    ssl:connect(Addr, Port, ConnectOpts, ConnectTime).


listen(Opts) ->
    case proplists:get_value(lsock, Opts, undefined) of
        undefined ->
            Addr = proplists:get_value(addr, Opts, default_addr()),
            Port = proplists:get_value(port, Opts, ?DEFAULT_SMPP_PORT),
            listen(Port, ?LISTEN_OPTS(Addr), Opts);
        LSock ->
            Addr = proplists:get_value(addr, Opts, default_addr()),
            case inet:setopts(LSock, ?LISTEN_OPTS(Addr)) of
                ok ->
                    {ok, LSock};
                Error ->
                    Error
            end
    end.


listen(Port, LOpts, Opts) ->

    CertFile = proplists:get_value(certfile, Opts),

    case CertFile of
        undefined -> gen_tcp:listen(Port, LOpts);
        _ -> listen_ssl(Port, LOpts, Opts)
    end.


listen_ssl(Port, LOpts0, Opts) ->
    CertFile = proplists:get_value(certfile, Opts),
    KeyFile = proplists:get_value(keyfile, Opts),
    LOpts1 =
        [{certfile, CertFile},
        {keyfile, KeyFile} | LOpts0],

    CACertFile = proplists:get_value(cacertfile, Opts),
    LOpts2 =
    case CACertFile of
        undefined -> LOpts1;
        _ -> [{cacertfile, CACertFile} | LOpts1]
    end,

    Versions = proplists:get_value(versions, Opts),
    LOpts =
    case Versions of
        undefined -> LOpts2;
        _ -> [{versions, Versions} | LOpts2]
    end,

    ssl:listen(Port, LOpts).


tcp_send(Sock, Data) when is_port(Sock) ->
    try erlang:port_command(Sock, Data) of
        true -> ok
    catch
        error:_Error -> {error, einval}
    end;


tcp_send(Sock, Data) ->
    ssl:send(Sock, Data).


send_pdu(Sock, BinPdu, Log) when is_list(BinPdu) ->
    case tcp_send(Sock, BinPdu) of
        ok ->
            ok = smpp_log_mgr:pdu(Log, {out, BinPdu});
        {error, Reason} ->
            gen_statem:cast(self(), {sock_error, Reason})
    end;


send_pdu(Sock, Pdu, Log) ->
    case smpp_operation:pack(Pdu) of
        {ok, BinPdu} ->
            send_pdu(Sock, BinPdu, Log);
        {error, _CmdId, Status, _SeqNum} ->
            close(Sock),
            exit({command_status, Status})
    end.


controlling_process(Sock, Pid) when is_port(Sock) ->
    gen_tcp:controlling_process(Sock, Pid);


controlling_process(SSLSock, Pid) ->
    ssl:controlling_process(SSLSock, Pid).


close(Sock) when is_port(Sock) ->
    catch(gen_tcp:close(Sock));


close(SSLSock) ->
    ssl:close(SSLSock).

%%%-----------------------------------------------------------------------------
%%% SOCKET LISTENER FUNCTIONS
%%%-----------------------------------------------------------------------------
wait_accept(Pid, LSock, Log) when is_port(LSock) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            handle_accept(Pid, LSock, Log, Sock);
        {error, Reason} ->
            gen_statem:cast(Pid, {listen_error, Reason})
    end;


wait_accept(Pid, LSock, Log) ->
    case ssl:transport_accept(LSock) of
        {ok, Sock} ->
            case ssl:ssl_accept(Sock) of
                ok -> handle_accept(Pid, LSock, Log, Sock);
                {error, Reason} ->
                    gen_statem:cast(Pid, {handshake_error, Reason})
            end;
        {error, Reason} ->
            gen_statem:cast(Pid, {listen_error, Reason})
    end.


handle_accept(Pid, LSock, Log, Sock) ->
    case handle_accept(Pid, Sock) of
        true ->
            ?MODULE:recv_loop(Pid, Sock, <<>>, Log);
        false ->
            close(Sock),
            ?MODULE:wait_accept(Pid, LSock, Log)
    end.


wait_recv(Pid, Sock, Log) ->
    receive activate -> ?MODULE:recv_loop(Pid, Sock, <<>>, Log) end.


recv_loop(Pid, Sock, Buffer, Log) ->
    Timestamp = ?NOW,
    setopts(Sock, [{active, once}]),
    receive
        {Transport, Sock, Input} when
              Transport =:= tcp orelse
              Transport =:= ssl ->
            L = timer:now_diff(?NOW, Timestamp),
            B = handle_input(Pid, list_to_binary([Buffer, Input]), L, 1, Log),
            ?MODULE:recv_loop(Pid, Sock, B, Log);
        {TransportClosed, Sock} when
              TransportClosed =:= tcp_closed orelse
              TransportClosed =:= ssl_closed ->
            gen_statem:cast(Pid, {sock_error, closed});
        {TransportError, Sock, Reason} when
              TransportError =:= tcp_error orelse
              TransportError =:= ssl_error ->
            gen_statem:cast(Pid, {sock_error, Reason})
    end.


setopts(Sock, Opts) when is_port(Sock) ->
    inet:setopts(Sock, Opts);


setopts(Sock, Opts) ->
    ssl:setopts(Sock, Opts).

%%%-----------------------------------------------------------------------------
%%% TIMER FUNCTIONS
%%%-----------------------------------------------------------------------------
cancel_timer(undefined) ->
    false;
cancel_timer(Ref) ->
    erlang:cancel_timer(Ref).


start_timer(#timers_smpp{response_time = infinity}, {response_timer, _}) ->
    undefined;
start_timer(#timers_smpp{response_time = infinity}, enquire_link_failure) ->
    undefined;
start_timer(#timers_smpp{enquire_link_time = infinity}, enquire_link_timer) ->
    undefined;
start_timer(#timers_smpp{session_init_time = infinity}, session_init_timer) ->
    undefined;
start_timer(#timers_smpp{inactivity_time = infinity}, inactivity_timer) ->
    undefined;
start_timer(#timers_smpp{smsc_inactivity_time = infinity}, smsc_inactivity_timer) ->
    undefined;
start_timer(#timers_smpp{response_time = Time}, {response_timer, _} = Msg) ->
    erlang:start_timer(Time, self(), Msg);
start_timer(#timers_smpp{response_time = Time}, enquire_link_failure) ->
    erlang:start_timer(Time, self(), enquire_link_failure);
start_timer(#timers_smpp{enquire_link_time = Time}, enquire_link_timer) ->
    erlang:start_timer(Time, self(), enquire_link_timer);
start_timer(#timers_smpp{session_init_time = Time}, session_init_timer) ->
    erlang:start_timer(Time, self(), session_init_timer);
start_timer(#timers_smpp{smsc_inactivity_time = Time}, smsc_inactivity_timer) ->
    erlang:start_timer(Time, self(), smsc_inactivity_timer);
start_timer(#timers_smpp{inactivity_time = Time}, inactivity_timer) ->
    erlang:start_timer(Time, self(), inactivity_timer).

%%%-----------------------------------------------------------------------------
%%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
default_addr() ->
    {ok, Host} = inet:gethostname(),
    {ok, Addr} = inet:getaddr(Host, inet),
    Addr.


handle_accept(Pid, Sock) when is_port(Sock) ->
    case inet:peername(Sock) of
        {ok, {Addr, Port}} ->
            gen_statem:call(Pid, {accept, Sock, Addr, Port});
        {error, _Reason} ->  % Most probably the socket is closed
            false
    end;


handle_accept(Pid, Sock) ->
    case ssl:peername(Sock) of
        {ok, {Addr, Port}} ->
            gen_statem:call(Pid, {accept, Sock, Addr, Port});
        {error, _Reason} ->  % Most probably the socket is closed
            false
    end.


handle_input(Pid, <<CmdLen:32, Rest/binary>> = Buffer, Lapse, N, Log) ->
    Now = ?NOW, % PDU received.  PDU handling starts now!
    Len = CmdLen - 4,
    case Rest of
        <<PduRest:Len/binary-unit:8, NextPdus/binary>> ->
            BinPdu = <<CmdLen:32, PduRest/binary>>,
            case catch smpp_operation:unpack(BinPdu) of
                {ok, Pdu} ->
                    smpp_log_mgr:pdu(Log, {in, BinPdu}),
                    CmdId = smpp_operation:get_value(command_id, Pdu),
                    Event = {input, CmdId, Pdu, (Lapse div N), Now},
                    gen_statem:cast(Pid, Event);
                {error, _CmdId, _Status, _SeqNum} = Event ->
                    gen_statem:cast(Pid, Event);
                {'EXIT', _What} ->
                    Event = {error, 0, ?ESME_RUNKNOWNERR, 0},
                    gen_statem:cast(Pid, Event)
            end,
            % The buffer may carry more than one SMPP PDU.
            handle_input(Pid, NextPdus, Lapse, N + 1, Log);
        _IncompletePdu ->
            Buffer
    end;
handle_input(_Pid, Buffer, _Lapse, _N, _Log) ->
    Buffer.
