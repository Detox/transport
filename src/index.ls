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
 *
 * @return {!Uint8Array} Signature
 */
function sign (data)
	void
/**
 * @interface
 *
 * @param {!Uint8Array} data
 * @param {!Uint8Array} signature
 * @param {!Uint8Array} public_key	Ed25519 public key
 *
 * @return {boolean}
 */
function verify (data, signature, public_key)
	void

function Transport (webtorrent-dht, ronion, jssha, async-eventer)
	webrtc-socket	= webtorrent-dht({bootstrap: []})._rpc.socket.socket
	# TODO: Dirty hack in order to not include simple-peer second time on frontend
	simple-peer		= webrtc-socket._simple_peer_constructor
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
		 * @param {Uint8Array}	data
		 * @param {number}		command 1..255 - routing data command being sent
		 */
		..send_routing_data = (data, command) !->
			@real_send(data, command)
		/**
		 * Actual data sending method moved here
		 *
		 * @param {Uint8Array}	data
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
	 * @constructor
	 *
	 * @param {!Uint8Array}	public_key		Ed25519 public key
	 * @param {string[]}	bootstrap_nodes
	 * @param {!Object[]}	ice_servers
	 * @param {!sign}		sign
	 * @param {!verify}		verify
	 * @param {number}		bucket_size
	 *
	 * @return {DHT}
	 */
	!function DHT (public_key, bootstrap_nodes, ice_servers, sign, verify, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(public_key, bootstrap_nodes, ice_servers, sign, verify, bucket_size)
		async-eventer.call(@)
		@_socket	= webrtc-socket(
			simple_peer_constructor	: simple-peer-detox
			simple_peer_opts		:
				config	:
					iceServers	: ice_servers
				sign	: sign
		)
		@_socket
			..on('node_connected', (string_id) !~>
				id				= hex2array(string_id)
				peer_connection	= @_socket.get_id_mapping(string_id)
				# Already Uint8Array, no need to convert SDP to array
				if !verify(peer_connection._sdp_received, peer_connection._signature_received, id)
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
		@_dht	= new DHT(
			bootstrap	: bootstrap_nodes
			hash		: sha3_256
			k			: bucket_size
			nodeId		: public_key
			socket		: @_socket
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
		 * @param {Uint8Array} id
		 */
		..'lookup' = (id) !->
			@_dht.lookup(array2hex(id))
		/**
		 * Tag connection to specified node ID as used, so that it is not disconnected when not used by DHT itself
		 *
		 * @param {Uint8Array} id
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
		 * @param {Uint8Array} id
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
		 * @param {Uint8Array} id
		 * @param {Uint8Array} data
		 */
		..'send_data' = (id, data) !->
			string_id		= array2hex(id)
			peer_connection	= @_socket.get_id_mapping(string_id)
			if peer_connection
				peer_connection.send_routing_data(data, COMMAND_DATA)
		#TODO: more methods needed
		/**
		 * @param {Function} callback
		 */
		..'destroy' = (callback) !->
			# TODO: destroying should disconnect from any peers
			@_dht.destroy(callback)
			delete @_dht
	Object.defineProperty(DHT::, 'constructor', {enumerable: false, value: DHT})
	{
		'DHT'	: DHT
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['webtorrent-dht', 'ronion', 'jssha/src/sha3', 'async-eventer'], Transport)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Transport(require('webtorrent-dht'), require('ronion'), require('jssha/src/sha3'), require('async-eventer'))
else
	# Browser globals
	@'detox_transport' = Transport(@'webtorrent_dht', @'ronion', @'jsSHA', @'async_eventer')
