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

function Transport (detox-dht, ronion, jssha, async-eventer)
	simple-peer		= detox-dht.simple-peer
	webrtc-socket	= detox-dht.webrtc-socket
	webtorrent-dht	= detox-dht.webtorrent-dht
	Buffer			= detox-dht.Buffer
	/**
	 * We'll authenticate remove peers by requiring them to sign SDP by their DHT key
	 *
	 * @constructor
	 *
	 * @param {!Array} options
	 */
	!function simple-peer-detox (options)
		if !(@ instanceof simple-peer-detox)
			return new simple-peer-detox(options)
		@_sign	= options.sign
		simple-peer.call(@, options)

	simple-peer-detox:: = Object.create(simple-peer::)
	simple-peer-detox::
		/**
		 * Dirty hack to get `data` event and handle it the way we want
		 */
		..emit = (event, data) !->
			switch event
				case 'signal'
					data.signature	= @_sign(string2array(data.sdp))
					simple-peer::emit.apply(@, data)
				case 'data'
					command	= data[0]
					if command == COMMAND_DHT
						simple-peer::emit.call(@, 'data', data.subarray(1))
					else
						simple-peer::emit.call(@, 'routing_data', command, data.subarray(1))
				else
					simple-peer::emit.apply(@, &)
		/**
		 * @param {!Object} signal
		 */
		..signal = (signal) !->
			if !signal.signature
				# Drop connection if signature not specified
				@destroy()
			@_signature_received	= signal.signature
			# Already Uint8Array, no need to convert SDP to array
			@_sdp_received			= signal.sdp
			simple-peer::emit.call(@, signal)
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {Buffer} data
		 */
		..send = (data) !->
			@real_send(data, COMMAND_DHT)
		/**
		 * Data sending method that will be used by anonymous routing
		 *
		 * @param {!Uint8Array}	data
		 * @param {number}		command 1..255 - routing data command being sent
		 */
		..send_routing_data = (data, command) !->
			@real_send(data, command)
		/**
		 * Actual data sending method moved here
		 *
		 * @param {!Uint8Array}	data
		 * @param {number}		command
		 */
		..real_send = (data, command) !->
			data_with_header	= new Uint8Array(data.length + 1)
				..set([command])
				..set(data, 1)
			simple-peer::send.call(@, data_with_header)

	Object.defineProperty(simple-peer-detox::, 'constructor', {enumerable: false, value: simple-peer-detox})
	/**
	 * @param {!Uint8Array} data
	 *
	 * @return {string}
	 */
	function sha3_256 (data)
		shaObj = new jsSHA('SHA3-256', 'ARRAYBUFFER');
		shaObj.update(array)
		shaObj.getHash('HEX')
	/**
	 * @param {!Object} message
	 *
	 * @return {!Buffer}
	 */
	function encode_signature_data (message)
		ref =
			seq	: message.seq
			v	: message.v
		bencode.encode(ref).slice(1, -1)
	/**
	 * @constructor
	 *
	 * TODO: constant bandwidth utilization using extensions to transfer info
	 *
	 * @param {!Uint8Array}	public_key		Ed25519 public key, temporary one, just for DHT operation
	 * @param {!Uint8Array}	private_key		Corresponding Ed25519 private key
	 * @param {string[]}	bootstrap_nodes
	 * @param {!Object[]}	ice_servers
	 * @param {!sign}		sign
	 * @param {!verify}		verify
	 * @param {number}		bucket_size
	 *
	 * @return {DHT}
	 */
	!function DHT (public_key, private_key, bootstrap_nodes, ice_servers, sign, verify, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(public_key, private_key, bootstrap_nodes, ice_servers, sign, verify, bucket_size)
		async-eventer.call(@)
		@_sign		= sign
		@_socket	= webrtc-socket(
			simple_peer_constructor	: simple-peer-detox
			simple_peer_opts		:
				config	:
					iceServers	: ice_servers
				sign	: (data) ->
					sign(data, public_key, private_key)
		)
		@_socket
			..on('node_connected', (string_id) !~>
				id				= hex2array(string_id)
				peer_connection	= @_socket.get_id_mapping(string_id)
				# Already Uint8Array, no need to convert SDP to array
				if !verify(peer_connection._signature_received, peer_connection._sdp_received, id)
					# Drop connection if node failed to sign SDP with its public message
					peer_connection.destroy()
				peer_connection.on('routing_data', (command, data) !~>
					switch command
						case COMMAND_TAG
							@_socket.add_tag(string_id, 'detox-responder')
							@fire('node_tagged', id)
						case COMMAND_UNTAG
							@_socket.del_tag(string_id, 'detox-responder')
							@fire('node_untagged', id)
						case COMMAND_DATA
							@fire('data', id, data)
				)
				@fire('node_connected', id)
			)
			..on('node_disconnected', (string_id) !~>
				@fire('node_disconnected', hex2array(string_id))
			)
		@_dht	= new webtorrent-dht(
			bootstrap	: bootstrap_nodes
			hash		: sha3_256
			k			: bucket_size
			nodeId		: public_key
			socket		: @_socket
			verify		: verify
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
			peer_connection	= @_socket.get_id_mapping(string_id)
			if peer_connection
				peer_connection.send_routing_data(new Uint8Array(0), COMMAND_TAG)
				@_socket.add_tag(string_id, 'detox-initiator')
		/**
		 * Remove tag from connection, so that it can be disconnected if not needed by DHT anymore
		 *
		 * @param {!Uint8Array} id
		 */
		..'del_used_tag' = (id) !->
			string_id	= array2hex(id)
			peer_connection	= @_socket.get_id_mapping(string_id)
			if peer_connection
				peer_connection.send_routing_data(new Uint8Array(0), COMMAND_UNTAG)
				@_socket.del_tag(string_id, 'detox-initiator')
		/**
		 * Send data to specified node ID
		 *
		 * @param {!Uint8Array} id
		 * @param {!Uint8Array} data
		 */
		..'send_data' = (id, data) !->
			string_id		= array2hex(id)
			peer_connection	= @_socket.get_id_mapping(string_id)
			if peer_connection
				peer_connection.send_routing_data(data, COMMAND_DATA)
		/**
		 * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
		 *
		 * @param {!Uint8Array}		public_key			Ed25519 public key (real one, different from supplied in DHT constructor)
		 * @param {!Uint8Array}		private_key			Corresponding Ed25519 private key
		 * @param {!Uint8Array[]}	introduction_points	Array of public keys of introduction points
		 *
		 * @return {!Object}
		 */
		..'generate_introduction_message' = (public_key, private_key, introduction_points) !->
			time	= +(new Date)
			value	= new Uint8Array(introduction_points.length * PUBLIC_KEY_LENGTH)
			for introduction_point, index in introduction_points
				value.set(introduction_point, index * PUBLIC_KEY_LENGTH)
			signature_data	= encode_signature_data(
				seq	: time
				v	: value
			)
			signature		= @_sign(signature_data, public_key, private_key)
			# This message has signature, so it can be now sent from any node in DHT
			{
				k	: public_key
				seq	: time
				sig	: signature
				v	: value
			}
		/**
		 * Publish message with introduction nodes (typically happens on different node than `generate_introduction_message()`)
		 *
		 * @param {!Object} message
		 */
		..'publish_introduction_message' = (message) !->
			if !message.k || !message.seq || !message.sig || !message.v
				return
			@_dht.put(
				k	: Buffer.from(message.public_key)
				seq	: message.time
				sig	: Buffer.from(message.signature)
				v	: Buffer.from(message.value)
			)
		/**
		 * Find nodes in DHT that are acting as introduction points for specified public key
		 *
		 * @param {!Uint8Array}					public_key
		 * @param {!found_introduction_points}	callback
		 */
		..'find_introduction_points' = (public_key, callback) !->
			hash	= sha3_256(public_key)
			@_dht.get(hash, (result) !->
				introduction_points_bulk	= Uint8Array.from(result.v)
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
			@_dht.destroy(callback)
			delete @_dht
	Object.defineProperty(DHT::, 'constructor', {enumerable: false, value: DHT})
	{
		'DHT'	: DHT
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/dht', 'ronion', 'jssha/src/sha3', 'async-eventer'], Transport)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Transport(require('@detox/dht'), require('ronion'), require('jssha/src/sha3'), require('async-eventer'))
else
	# Browser globals
	@'detox_transport' = Transport(@'detox_dht', @'ronion', @'jsSHA', @'async_eventer')
