/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
# 65 KiB is what is enough for DHT messages and will also be enough for routing data, bigger data will be multiplexed on higher levels when necessary
const MAX_DATA_SIZE				= 2 ** 16 - 2
const MAX_COMPRESSED_DATA_SIZE	= MAX_DATA_SIZE - 1
# Fixed packet size for all communications on peer connection
const PACKET_SIZE				= 512
# If connection was not established during this time (seconds) then assume connection failure
const PEER_CONNECTION_TIMEOUT	= 30

/**
 * @param {!Array<!Uint8Array>}	buffer
 * @param {!Uint8Array}			new_array
 */
!function update_dictionary_buffer (buffer, new_array)
	buffer[0]	= buffer[1]
	buffer[1]	= buffer[2]
	buffer[2]	= buffer[3]
	buffer[3]	= buffer[4]
	buffer[4]	= new_array

/**
 * @param {!Object=} wrtc
 */
function Wrapper (detox-utils, fixed-size-multiplexer, async-eventer, pako, simple-peer, wrtc)
	array2string	= detox-utils['array2string']
	string2array	= detox-utils['string2array']
	concat_arrays	= detox-utils['concat_arrays']
	ArrayMap		= detox-utils['ArrayMap']
	timeoutSet		= detox-utils['timeoutSet']
	null_array		= new Uint8Array(0)
	/**
	 * @constructor
	 *
	 * @param {boolean}			initiator
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packets_per_second				Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			uncompressed_commands_offset	Commands with number less than this will be compressed/decompressed with zlib
	 *
	 * @return {!P2P_transport}
	 */
	!function P2P_transport (initiator, ice_servers, packets_per_second, uncompressed_commands_offset)
		if !(@ instanceof P2P_transport)
			return new P2P_transport(initiator, ice_servers, packets_per_second, uncompressed_commands_offset)
		async-eventer.call(@)

		@_initiator						= initiator
		@_uncompressed_commands_offset	= uncompressed_commands_offset
		@_peer							= simple-peer(
			'config'	:
				'iceServers'	: ice_servers
			'initiator'	: initiator
			'trickle'	: false
			'wrtc'		: wrtc
		)

		@_send_delay			= 1000 / packets_per_second
		@_sending				= initiator
		@_multiplexer			= fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, PACKET_SIZE)
		@_demultiplexer			= fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, PACKET_SIZE)
		@_send_zlib_buffer		= [null_array, null_array, null_array, null_array, null_array]
		@_receive_zlib_buffer	= [null_array, null_array, null_array, null_array, null_array]
		@_peer
			..once('signal', (signal) !~>
				if @_destroyed
					return
				@'fire'('signal', string2array(signal['sdp']))
			)
			..'once'('connect', !~>
				if @_destroyed
					return
				@'fire'('connected')
				@_last_sent	= +(new Date)
				if @_sending
					@_real_send()
			)
			..'once'('close', !~>
				@'fire'('disconnected')
			)
			..'on'('data', (data) !~>
				if @_destroyed
					return
				# Data are sent in alternating order, sending data when receiving is expected violates the protocol
				# Data size must be exactly one packet size
				if @_sending || data.length != PACKET_SIZE
					@'destroy'()
				else
					@_demultiplexer['feed'](data)
					while @_demultiplexer['have_more_data']()
						demultiplexed_data	= @_demultiplexer['get_data']()
						command				= demultiplexed_data[0]
						command_data		= demultiplexed_data.subarray(1)
						if command < @_uncompressed_commands_offset
							command_data	= @_zlib_decompress(command_data)
						@'fire'('data', command, command_data)
					@_sending	= true
					@_real_send()
			)

	P2P_transport:: =
		/**
		 * @param {!Uint8Array} signal As generated by `signal` event
		 */
		'signal' : (signal) !->
			if @_destroyed
				return
			@_peer['signal'](
				'type'	: if @_initiator then 'answer' else 'offer'
				'sdp'	: array2string(signal)
			)
		/**
		 * @param {number}		command
		 * @param {!Uint8Array}	data
		 */
		'send' : (command, data) !->
			if @_destroyed || data.length > MAX_DATA_SIZE
				return
			# We only compress DHT commands data
			if command < @_uncompressed_commands_offset
				if data.length > MAX_COMPRESSED_DATA_SIZE
					return
				data	= @_zlib_compress(data)
			data_with_header	= concat_arrays([[command], data])
			@_multiplexer['feed'](data_with_header)
		'destroy' : !->
			if @_destroyed
				return
			@_destroyed	= true
			clearTimeout(@_timeout)
			@_peer['destroy']()
		/**
		 * Send a block of multiplexed data to the other side
		 */
		_real_send : !->
			# Subtract from necessary delay actual amount of time already passed and make sure it is not negative
			delay		= Math.max(0, @_send_delay - (new Date - @_last_sent))
			@_timeout	= setTimeout (!~>
				if @_destroyed
					return
				# In rare cases we might get exceptions like `InvalidStateError`, don't let the whole thing crash because of this
				try
					@_peer['send'](@_multiplexer['get_block']())
					@_sending	= false
					@_last_sent	= +(new Date)
			), delay
		/**
		 * @param {!Uint8Array} data
		 *
		 * @return {!Uint8Array}
		 */
		_zlib_compress : (data) ->
			result	= pako['deflate'](data, {
				'dictionary'	: concat_arrays(@_send_zlib_buffer)
				'level'			: 1
			})
			update_dictionary_buffer(@_send_zlib_buffer, data)
			if result.length > MAX_COMPRESSED_DATA_SIZE
				concat_arrays([[0], data])
			else
				concat_arrays([[1], result])
		/**
		 * @param {!Uint8Array} data
		 *
		 * @return {!Uint8Array}
		 */
		_zlib_decompress : (data) ->
			compressed	= data[0]
			data		= data.subarray(1)
			if compressed
				result	= pako['inflate'](data, {
					'dictionary'	: concat_arrays(@_receive_zlib_buffer)
				})
			else
				result	= data
			update_dictionary_buffer(@_receive_zlib_buffer, result)
			result
	P2P_transport:: = Object.assign(Object.create(async-eventer::), P2P_transport::)
	Object.defineProperty(P2P_transport::, 'constructor', {value: P2P_transport})
	/**
	 * @constructor
	 *
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packets_per_second				Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			uncompressed_commands_offset	Commands with number less than this will be compressed/decompressed with zlib
	 * @param {number}			connect_timeout					How many seconds since `signal` generation to wait for connection before failing
	 *
	 * @return {!Transport}
	 */
	!function Transport (ice_servers, packets_per_second, uncompressed_commands_offset, connect_timeout)
		if !(@ instanceof Transport)
			return new Transport(ice_servers, packets_per_second, uncompressed_commands_offset, connect_timeout)
		async-eventer.call(@)

		@_pending_connections			= ArrayMap()
		@_connections					= ArrayMap()
		@_timeouts						= new Set
		@_ice_servers					= ice_servers
		@_packets_per_second			= packets_per_second
		@_uncompressed_commands_offset	= uncompressed_commands_offset
		@_connect_timeout				= connect_timeout

	Transport:: =
		/**
		 * @param {boolean}		initiator
		 * @param {!Uint8Array}	peer_id
		 */
		'create_connection' : (initiator, peer_id) !->
			if @_destroyed || @_pending_connections.has(peer_id) || @_connections.has(peer_id)
				return
			connection	= P2P_transport(initiator, @_ice_servers, @_packets_per_second, @_uncompressed_commands_offset)
				.'on'('data', (command, command_data) !~>
					if @_destroyed
						return
					@'fire'('data', peer_id, command, command_data)
				)
				.'once'('signal', (signal) !~>
					if @_destroyed
						return
					@'fire'('signal', peer_id, signal)
					@_connection_timeout(connection)
				)
				.'once'('connected', !~>
					if @_destroyed || !@_pending_connections.has(peer_id)
						return
					@_pending_connections.delete(peer_id)
					@_connections.set(peer_id, connection)
					@'fire'('connected', peer_id)
				)
				.'once'('disconnected', !~>
					if @_destroyed
						return
					@_pending_connections.delete(peer_id)
					@_connections.delete(peer_id)
					@'fire'('disconnected', peer_id)
				)
			if !initiator
				# Responder might never fire `signal` event, so create timeout here
				@_connection_timeout(connection)
			@_pending_connections.set(peer_id, connection)
		/**
		 * @param {!P2P_transport} connection
		 */
		_connection_timeout : (connection) !->
			timeout	= timeoutSet(@_connect_timeout, !->
				connection['destroy']()
			)
			@_timeouts.add(timeout)
			connection['once']('connected', !~>
				@_timeouts.delete(timeout)
				clearTimeout(timeout)
			)
		/**
		 * @param {!Uint8Array} peer_id
		 */
		'destroy_connection' : (peer_id) !->
			connection	= @_pending_connections.get(peer_id) || @_connections.get(peer_id)
			if connection
				connection['destroy']()
		/**
		 * @param {!Uint8Array} peer_id
		 * @param {!Uint8Array} signal
		 */
		'signal' : (peer_id, signal) !->
			if @_destroyed
				return
			connection	= @_pending_connections.get(peer_id)
			if connection
				connection['signal'](signal)
		/**
		 * @param {!Uint8Array}	peer_id
		 * @param {number}		command
		 * @param {!Uint8Array}	command_data
		 */
		'send' : (peer_id, command, command_data) !->
			if @_destroyed
				return
			connection	= @_connections.get(peer_id)
			if connection
				connection['send'](command, command_data)
		'destroy' : !->
			if @_destroyed
				return
			@_destroyed	= true
			@_pending_connections.forEach (connection) !->
				connection['destroy']()
			@_connections.forEach (connection) !->
				connection['destroy']()
			@_timeouts.forEach (timeout) !->
				clearTimeout(timeout)
	Transport:: = Object.assign(Object.create(async-eventer::), Transport::)
	Object.defineProperty(Transport::, 'constructor', {value: Transport})
	{
		'P2P_transport'				: P2P_transport
		'Transport'					: Transport
		'MAX_DATA_SIZE'				: MAX_DATA_SIZE
		'MAX_COMPRESSED_DATA_SIZE'	: MAX_COMPRESSED_DATA_SIZE
	}

# NOTE: `wrtc` dependency is the last one and only specified for CommonJS, make sure to insert new dependencies before it
if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/utils', 'fixed-size-multiplexer', 'async-eventer', 'pako', '@detox/simple-peer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/utils'), require('fixed-size-multiplexer'), require('async-eventer'), require('pako'), require('@detox/simple-peer'), require('wrtc'))
else
	# Browser globals
	@'detox_transport' = Wrapper(@'detox_utils', @'fixed_size_multiplexer', @'async_eventer', @'pako', @'SimplePeer')
