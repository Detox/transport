/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
function Transport (webtorrent-dht, ronion, jssha, async-eventer)
	webrtc-socket	= webtorrent-dht({bootstrap: []})._rpc.socket.socket
	# TODO: Dirty hack in order to not include simple-peer second time on frontend
	simple-peer		= webrtc-socket._simple_peer_constructor
	/**
	 * We'll authenticate remove peers by requiring them to sign SDP by their DHT key
	 * TODO: ^ is not implemented yet
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
		 * Dirty hack to get `data` event and handle it the way we want
		 */
		..emit = (event, data) !->
			if event == 'data'
				if data[0] == 1 # DHT data
					simple-peer::emit.call(@, 'data', data.subarray(1))
				else # Routing data
					simple-peer::emit.call(@, 'routing_data', data.subarray(1))
			else
				simple-peer::emit.apply(@, &)
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {Buffer} data
		 */
		..send = (data) !->
			@real_send(data, true)
		/**
		 * Data sending method that will be used by anonymous routing
		 *
		 * @param {Uint8Array} data
		 */
		..send_routing_data = (data) !->
			@real_send(data, false)
		/**
		 * Actual data sending method moved here
		 *
		 * @param {Uint8Array}	data
		 * @param {boolean}		for_dht	Whether data sent are for DHT or not
		 */
		..real_send = (data, for_dht) !->
			data_with_header	= new Uint8Array(data.length + 1)
				..set([if for_dht then 1 else 0])
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
		async-eventer.call(@)
		socket	= webrtc-socket(
			simple_peer_constructor	: simple-peer-detox
			simple_peer_opts		:
				config	:
					iceServers	: ice_servers
		)
		socket
			..on('node_connected', (id) !~>
				@fire('node_connected', id)
			)
			..on('node_disconnected', (id) !~>
				@fire('node_disconnected', id)
			)
		@_dht	= new DHT(
			bootstrap	: bootstrap_nodes
			hash		: sha3_256
			k			: bucket_size
			nodeId		: node_id
			socket		: socket
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
