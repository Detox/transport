/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
function Transport (webtorrent-dht, ronion, jssha)
	webrtc-socket	= webtorrent-dht({bootstrap: []})._rpc.socket.socket
	# TODO: Dirty hack in order to not include simple-peer second time on frontend
	simple-peer		= webrtc-socket._simple_peer_constructor
	/**
	 * @constructor
	 *
	 * @param {!Array} options
	 */
	!function webrtc-socket-detox (options)
		if !(@ instanceof webrtc-socket-detox)
			return new webrtc-socket-detox(options)
		webrtc-socket.call(@, options)

	webrtc-socket-detox:: = Object.create(webrtc-socket::)
	webrtc-socket-detox::
		/**
		 * We'll reuse single WebRTC connection for both DHT and anonymous routing,
		 * so we don't want to immediately disconnect from the node as soon as it is not used by DHT
		 *
		 * @param {string} id
		 */
		..del_id_mapping = (id) !->
			peer_connection	= @get_id_mapping(id)
			# TODO: assign `_used_by_detox` property
			if peer_connection.connected && !peer_connection.destroyed && peer_connection._used_by_detox
				# Do not actually disconnect from the node that is actively used by Detox
				return
			webrtc-socket::del_id_mapping(id)

	Object.defineProperty(webrtc-socket-detox::, 'constructor', {enumerable: false, value: webrtc-socket-detox})
	/**
	 * We'll authenticate remove peers by requiring them to sign SDP by their DHT key as well as will send all of the data in chunks of fixed size after
	 * fixed time intervals
	 *
	 * @constructor
	 *
	 * @param {!Array} options
	 */
	!function simple-peer-detox (options)
		if !(@ instanceof simple-peer-detox)
			return new simple-peer-detox(options)
		simple-peer.call(@, options)

	simple-peer-detox:: = Object.create(simple-peer::)
	simple-peer-detox::
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {Buffer} data
		 */
		..send = (data) !->
			@real_send(data, true)
		..send_routing (data) !->
			@real_send(data, false)
		/**
		 * Actual data sending method moved here
		 *
		 * @param {Uint8Array}	data
		 * @param {boolean}		for_dht	Whether data sent are for DHT or not
		 */
		..real_send = (data, for_dht) !->
			# TODO: Differentiate between DHT and anonymous routing here using `for_dht`
			simple-peer::send.call(@, data)

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
	 * @param {!Uint8Array}	node_id
	 * @param {!string[]}	bootstrap_nodes
	 * @param {!Object[]}	ice_servers
	 * @param {number}		bucket_size
	 *
	 * @return {DHT}
	 */
	!function DHT (node_id, bootstrap_nodes, ice_servers, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(node_id, bootstrap_nodes, ice_servers, bucket_size)
		@_dht	= new DHT(
			bootstrap			: bootstrap_nodes
			hash				: sha3_256
			k					: bucket_size
			nodeId				: node_id
			socket				: webrtc-socket-detox(
				simple_peer_constructor	: simple-peer-detox
				simple_peer_opts		:
					config	:
						iceServers	: ice_servers
			)
		)
	DHT::	=
		/**
		 * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {number}	port
		 * @param {string}	ip
		 */
		start_bootstrap_node : (port, ip) !->
			@_dht.listen(port, ip)
		/**
		 * @return {!string[]}
		 */
		get_bootstrap_nodes : ->
			@_dht.toJSON().nodes
		#TODO: more methods needed
		/**
		 * @param {Function} callback
		 */
		'destroy' : (callback) !->
			@_dht.destroy(callback)
			delete @_dht
	Object.defineProperty(DHT::, 'constructor', {enumerable: false, value: DHT})
	{
		'DHT'	: DHT
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['webtorrent-dht', 'ronion', 'jssha/src/sha3'], Transport)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Transport(require('webtorrent-dht'), require('ronion'), require('jssha/src/sha3'))
else
	# Browser globals
	@'detox_transport' = Transport(@'webtorrent_dht', @'ronion', @'jsSHA')
