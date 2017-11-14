/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
function Transport (webtorrent-dht, ronion, jssha)
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
	 *
	 * @return {DHT}
	 */
	!function DHT (node_id, bootstrap_nodes, ice_servers)
		if !(@ instanceof DHT)
			return new DHT(node_id, bootstrap_nodes, ice_servers)
		@_dht	= new DHT(
			nodeId				: node_id
			bootstrap			: bootstrap_nodes
			hash				: sha3_256
			simple_peer_opts	:
				config	:
					iceServers	: ice_servers
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
