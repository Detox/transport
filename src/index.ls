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
		# TODO: Timeouts (PEER_CONNECTION_TIMEOUT)?
		# TODO: Signatures here?
		@_peer							= simple-peer(
			'config'	:
				'iceServers'	: ice_servers
			'initiator'	: initiator
			'trickle'	: false
			'wrtc'		: wrtc
		)

		@_signal						= new Promise (resolve, reject) !~>
			@_peer
				..'once'('signal', (signal) !~>
					resolve(string2array(signal['sdp']))
				)
				..'once'('close', reject)
		@_signal.catch(->)

		@_send_delay			= 1000 / packets_per_second
		@_sending				= initiator
		@_multiplexer			= fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, PACKET_SIZE)
		@_demultiplexer			= fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, PACKET_SIZE)
		@_send_zlib_buffer		= [null_array, null_array, null_array, null_array, null_array]
		@_receive_zlib_buffer	= [null_array, null_array, null_array, null_array, null_array]
		@_peer
			..'once'('connect', !~>
				@'fire'('connected')
				@_last_sent	= +(new Date)
				if @_sending
					@_real_send()
			)
			..'once'('close', !~>
				@'fire'('disconnected')
			)
			..'on'('data', (data) !~>
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
		 * @return {!Promise} Resolves with `Uint8Array` signaling data
		 */
		'get_signaling' : ->
			@_signal
		/**
		 * @param {!Uint8Array} signaling As generated by `get_signaling()` method
		 */
		'set_signaling' : (signaling) !->
			@_peer['signal'](
				'type'	: if @_initiator then 'answer' else 'offer'
				'sdp'	: array2string(signaling)
			)
		/**
		 * @param {number}		command
		 * @param {!Uint8Array}	data
		 */
		'send' : (command, data) !->
			if data.length > MAX_DATA_SIZE
				return
			# We only compress DHT commands data
			if command < @_uncompressed_commands_offset
				if data.length > MAX_COMPRESSED_DATA_SIZE
					return
				data	= @_zlib_compress(data)
			data_with_header	= concat_arrays([[command], data])
			@_multiplexer['feed'](data_with_header)
		'destroy' : !->
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
	{
		'P2P_transport'				: P2P_transport
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
