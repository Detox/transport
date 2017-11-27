/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
const COMMAND_DHT	= 0
const COMMAND_DATA	= 1
const COMMAND_TAG	= 2
const COMMAND_UNTAG	= 3

# Length of Ed25519 public key in bytes
const PUBLIC_KEY_LENGTH	= 32
# Max data size of 16 MiB, more than enough for most purposes
const MAX_DATA_LENGTH	= 2**24 - 1

/**
 * @param {!Uint8Array} array
 *
 * @return {string}
 */
function array2hex (array)
	string = ''
	for byte in array
		string += byte.toString(16).padStart(2, 0)
	string
/**
 * @param {string} string
 *
 * @return {!Uint8Array}
 */
function hex2array (string)
	array	= new Uint8Array(string.length / 2)
	for i from 0 til array.length
		array[i] = parseInt(string.substring(i * 2, i * 2 + 2), 16)
	array
/**
 * @param {string} string
 *
 * @return {!Uint8Array}
 */
function string2array (string)
	array = new Uint8Array(string.length)
	for i from 0 til string.length
		array[i] = string.charCodeAt(i)
	array

/**
 * @interface
 *
 * Public and private key are implicitly assumed to correspond to current node's ones
 *
 * @param {!Uint8Array} data
 * @param {!Uint8Array} public_key
 * @param {!Uint8Array} private_key
 *
 * @return {!Uint8Array} Signature
 */
function sign (data, public_key, private_key)
	void
/**
 * @interface
 *
 * @param {!Uint8Array} signature
 * @param {!Uint8Array} data
 * @param {!Uint8Array} public_key	Ed25519 public key
 *
 * @return {boolean}
 */
function verify (signature, data, public_key)
	void
/**
 * @interface
 *
 * @param {!Uint8Array[]} introduction_points
 */
function found_introduction_points (introduction_points)
	void

function Transport (detox-dht, ronion, jssha, fixed-size-multiplexer, async-eventer)
	simple-peer		= detox-dht['simple-peer']
	webrtc-socket	= detox-dht['webrtc-socket']
	webtorrent-dht	= detox-dht['webtorrent-dht']
	Buffer			= detox-dht['Buffer']
	/**
	 * We'll authenticate remove peers by requiring them to sign SDP by their DHT key
	 *
	 * @constructor
	 *
	 * @param {!Object} options
	 */
	!function simple-peer-detox (options)
		if !(@ instanceof simple-peer-detox)
			return new simple-peer-detox(options)
		@_sign					= options.sign
		@_packet_size			= options.packet_size
		@_packets_per_second	= options.packets_per_second
		@_sending				= options.initiator
		@'once'('connect', !~>
			@_send_delay	= 1000 / @_packets_per_second
			@_multiplexer	= fixed-size-multiplexer['Multiplexer'](MAX_DATA_LENGTH, @_packet_size)
			@_demultiplexer	= fixed-size-multiplexer['Demultiplexer'](MAX_DATA_LENGTH, @_packet_size)
			@_last_sent		= +(new Date)
			if @_sending
				@_real_send()
		)
		simple-peer.call(@, options)

	simple-peer-detox:: = Object.create(simple-peer::)
	simple-peer-detox::
		/**
		 * Dirty hack to get `data` event and handle it the way we want
		 */
		..'emit' = (event, data) !->
			switch event
				case 'signal'
					data.signature	= @_sign(string2array(data['sdp']))
					simple-peer::['emit'].call(@, 'signal', data)
				case 'data'
					if @_sending
						# Data are sent in alternating order, sending data when receiving is expected violates the protocol
						@'destroy'()
						return
					else
						@_demultiplexer['feed'](data)
						if @_demultiplexer['have_more_data']()
							/**
							 * @type {!Uint8Array}
							 */
							actual_data = @_demultiplexer['get_data']()
							command		= actual_data[0]
							if command == COMMAND_DHT
								simple-peer::['emit'].call(@, 'data', actual_data.subarray(1))
							else
								simple-peer::['emit'].call(@, 'routing_data', command, actual_data.subarray(1))
						@_sending	= true
				else
					simple-peer::['emit'].apply(@, &)
		/**
		 * @param {!Object} signal
		 */
		..'signal' = (signal) !->
			if !signal.signature || !!signal['extensions']
				# Drop connection if signature or extensions not specified
				@'destroy'()
				return
			@_signature_received	= signal.signature
			# Already Uint8Array, no need to convert SDP to array
			@_sdp_received			= signal['sdp']
			found_psr				= false
			for extension in signal['extensions']
				if extension.startsWith('psr:')
					array						= extension.split(':')
					received_packet_size		= parseInt(array[1])
					received_packets_per_second	= parseInt(array[2])
					if received_packet_size < 1 || received_packets_per_second < 1
						@'destroy'()
						return
					@_packet_size			= Math.min(@_packet_size, received_packet_size)
					@_packets_per_second	= Math.min(@_packets_per_second, received_packets_per_second)
					found_psr				= true
					break
			if !found_psr
				@'destroy'()
				return
			simple-peer::['emit'].call(@, signal)
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {Buffer} data
		 */
		..'send' = (data) !->
			@_send_multiplex(data, COMMAND_DHT)
		/**
		 * Data sending method that will be used by anonymous routing
		 *
		 * @param {!Uint8Array}	data
		 * @param {number}		command 1..255 - routing data command being sent
		 */
		.._send_routing_data = (data, command) !->
			@_send_multiplex(data, command)
		/**
		 * Actual data sending method moved here
		 *
		 * @param {!Uint8Array}	data
		 * @param {number}		command
		 */
		.._send_multiplex = (data, command) !->
			data_with_header	= new Uint8Array(data.length + 1)
				..set([command])
				..set(data, 1)
			@_multiplexer['feed'](data_with_header)
		/**
		 * Send a block of multiplexed data to the other side
		 */
		.._real_send = !->
			# Subtract from necessary delay actual amount of time already passed and make sure it is not negative
			delay	= Math.max(0, @_send_delay - (new Date - @_last_sent))
			setTimeout (!~>
				if @_destroyed
					return
				simple-peer::['send'].call(@, @_multiplexer['get_block']())
				@_sending	= false
				@_last_sent	= +(new Date)
			), delay

	Object.defineProperty(simple-peer-detox::, 'constructor', {enumerable: false, value: simple-peer-detox})
	/**
	 * @param {!Uint8Array} data
	 *
	 * @return {string}
	 */
	function sha3_256 (data)
		shaObj = new jsSHA('SHA3-256', 'ARRAYBUFFER');
		shaObj['update'](array)
		shaObj['getHash']('HEX')
	/**
	 * @param {!Object} message
	 *
	 * @return {!Buffer}
	 */
	function encode_signature_data (message)
		bencode['encode'](message).slice(1, -1)
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}	public_key			Ed25519 public key, temporary one, just for DHT operation
	 * @param {!Uint8Array}	private_key			Corresponding Ed25519 private key
	 * @param {string[]}	bootstrap_nodes
	 * @param {!Object[]}	ice_servers
	 * @param {!sign}		sign
	 * @param {!verify}		verify
	 * @param {number}		packet_size
	 * @param {number}		packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}		bucket_size
	 *
	 * @return {DHT}
	 */
	!function DHT (public_key, private_key, bootstrap_nodes, ice_servers, sign, verify, packet_size, packets_per_second, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(public_key, private_key, bootstrap_nodes, ice_servers, sign, verify, packet_size, packets_per_second, bucket_size)
		async-eventer.call(@)
		if packets_per_second < 1
			packets_per_second	= 1
		@_sign		= sign
		@_socket	= webrtc-socket(
			'simple_peer_constructor'	: simple-peer-detox
			'simple_peer_opts'		:
				'config'				:
					'iceServers'	: ice_servers
				'packet_size'			: packet_size
				'packets_per_second'	: packets_per_second
				'sign'					: (data) ->
					sign(data, public_key, private_key)
		)
		@_socket
			..'on'('node_connected', (string_id) !~>
				id				= hex2array(string_id)
				peer_connection	= @_socket['get_id_mapping'](string_id)
				# Already Uint8Array, no need to convert SDP to array
				if !verify(peer_connection._signature_received, peer_connection._sdp_received, id)
					# Drop connection if node failed to sign SDP with its public message
					peer_connection['destroy']()
				peer_connection['on']('routing_data', (command, data) !~>
					switch command
						case COMMAND_TAG
							@_socket['add_tag'](string_id, 'detox-responder')
							@'fire'('node_tagged', id)
						case COMMAND_UNTAG
							@_socket['del_tag'](string_id, 'detox-responder')
							@'fire'('node_untagged', id)
						case COMMAND_DATA
							@'fire'('data', id, data)
				)
				@'fire'('node_connected', id)
			)
			..'on'('node_disconnected', (string_id) !~>
				@'fire'('node_disconnected', hex2array(string_id))
			)
		@_dht	= new webtorrent-dht(
			'bootstrap'		: bootstrap_nodes
			'extensions'	: [
				"psr:#packet_size:#packets_per_second" # Packet size and rate
			]
			'hash'			: sha3_256
			'k'				: bucket_size
			'nodeId'		: public_key
			'socket'		: @_socket
			'verify'		: verify
		)

	DHT:: = Object.create(async-eventer::)
	DHT::
		/**
		 * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {number}	port
		 * @param {string}	ip
		 */
		..'start_bootstrap_node' = (port, ip) !->
			@_dht.listen(port, ip)
		/**
		 * @return {!string[]}
		 */
		..'get_bootstrap_nodes' = ->
			@_dht.toJSON().nodes
		/**
		 * Start lookup for specified node ID (listen for `node_connected` in order to know when interested node was connected)
		 *
		 * @param {!Uint8Array} id
		 */
		..'lookup' = (id) !->
			@_dht.lookup(array2hex(id))
		/**
		 * Tag connection to specified node ID as used, so that it is not disconnected when not used by DHT itself
		 *
		 * @param {!Uint8Array} id
		 */
		..'add_used_tag' = (id) !->
			string_id	= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(new Uint8Array(0), COMMAND_TAG)
				@_socket['add_tag'](string_id, 'detox-initiator')
		/**
		 * Remove tag from connection, so that it can be disconnected if not needed by DHT anymore
		 *
		 * @param {!Uint8Array} id
		 */
		..'del_used_tag' = (id) !->
			string_id	= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(new Uint8Array(0), COMMAND_UNTAG)
				@_socket['del_tag'](string_id, 'detox-initiator')
		/**
		 * Send data to specified node ID
		 *
		 * @param {!Uint8Array} id
		 * @param {!Uint8Array} data
		 */
		..'send_data' = (id, data) !->
			string_id		= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(data, COMMAND_DATA)
		/**
		 * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
		 *
		 * @param {!Uint8Array}		public_key			Ed25519 public key (real one, different from supplied in DHT constructor)
		 * @param {!Uint8Array}		private_key			Corresponding Ed25519 private key
		 * @param {!Uint8Array[]}	introduction_points	Array of public keys of introduction points
		 *
		 * @return {!Object}
		 */
		..'generate_introduction_message' = (public_key, private_key, introduction_points) ->
			time	= +(new Date)
			value	= new Uint8Array(introduction_points.length * PUBLIC_KEY_LENGTH)
			for introduction_point, index in introduction_points
				value.set(introduction_point, index * PUBLIC_KEY_LENGTH)
			signature_data	= encode_signature_data(
				'seq'	: time
				'v'		: value
			)
			signature		= @_sign(signature_data, public_key, private_key)
			# This message has signature, so it can be now sent from any node in DHT
			{
				'k'		: public_key
				'seq'	: time
				'sig'	: signature
				'v'		: value
			}
		/**
		 * Publish message with introduction nodes (typically happens on different node than `generate_introduction_message()`)
		 *
		 * @param {!Object} message
		 */
		..'publish_introduction_message' = (message) !->
			if !message['k'] || !message['seq'] || !message['sig'] || !message['v']
				return
			@_dht['put'](
				'k'		: Buffer.from(message['k'])
				'seq'	: parseInt(message['seq'])
				'sig'	: Buffer.from(message['sig'])
				'v'		: Buffer.from(message['v'])
			)
		/**
		 * Find nodes in DHT that are acting as introduction points for specified public key
		 *
		 * @param {!Uint8Array}					public_key
		 * @param {!found_introduction_points}	callback
		 */
		..'find_introduction_points' = (public_key, callback) !->
			hash	= sha3_256(public_key)
			@_dht['get'](hash, (result) !->
				introduction_points_bulk	= Uint8Array.from(result['v'])
				introduction_points			= []
				if introduction_points_bulk.length % PUBLIC_KEY_LENGTH == 0
					return
				for i from 0 til introduction_points_bulk.length / PUBLIC_KEY_LENGTH
					introduction_points.push(introduction_points_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH))
				callback(introduction_points)
			)
		/**
		 * @param {Function} callback
		 */
		..'destroy' = (callback) !->
			@_dht['destroy'](callback)
			delete @_dht
	Object.defineProperty(DHT::, 'constructor', {enumerable: false, value: DHT})
	{
		'DHT'	: DHT
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/dht', 'ronion', 'jssha/src/sha3', 'fixed-size-multiplexer', 'async-eventer'], Transport)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Transport(require('@detox/dht'), require('ronion'), require('jssha/src/sha3'), require('fixed-size-multiplexer'), require('async-eventer'))
else
	# Browser globals
	@'detox_transport' = Transport(@'detox_dht', @'ronion', @'jsSHA', @'fixed_size_multiplexer', @'async_eventer')
