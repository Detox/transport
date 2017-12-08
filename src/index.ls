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

const ROUTING_PROTOCOL_VERSION		= 0
# Length of Ed25519 public key in bytes
const PUBLIC_KEY_LENGTH				= 32
# ChaChaPoly+BLAKE2b
const MAC_LENGTH					= 16
# Fixed minimal reasonable packet size, will definitely fit Noise handshake message and with non-zero chance DHT queries/responses; 512+ is recommended though
const MIN_PACKET_SIZE				= 256
# Max time in seconds allowed for routing path segment creation after which creation is considered failed
const ROUTING_PATH_SEGMENT_TIMEOUT	= 10
# 16 MiB is a reasonable size limit for text data, bigger data can be multiplexed on higher level if necessary
const MAX_DATA_SIZE					= 2 ** 24 - 1
# Same as in webtorrent-dht
const PEER_CONNECTION_TIMEOUT		= 30

/**
 * @param {!Uint8Array} array
 *
 * @return {string}
 */
function array2hex (array)
	string = ''
	for byte in array
		string += byte.toString(16).padStart(2, '0')
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
 * @param {string}		string
 * @param {!Uint8Array}	array
 *
 * @return {boolean}
 */
function is_string_equal_to_array (string, array)
	string == array.join(',')
/**
 * @param {!Uint8Array}	address
 * @param {!Uint8Array}	segment_id
 *
 * @return {string}
 */
function compute_source_id (address, segment_id)
	address.join(',') + segment_id.join(',')

function Transport (detox-crypto, detox-dht, ronion, jsSHA, fixed-size-multiplexer, async-eventer)
	bencode			= detox-dht['bencode']
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
		@_sign					= options['sign']
		@_packet_size			= options['packet_size']
		@_packets_per_second	= options['packets_per_second']
		@_sending				= options['initiator']
		@'once'('connect', !~>
			@_send_delay	= 1000 / @_packets_per_second
			@_multiplexer	= fixed-size-multiplexer['Multiplexer'](@_packet_size, @_packet_size)
			@_demultiplexer	= fixed-size-multiplexer['Demultiplexer'](@_packet_size, @_packet_size)
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
					data['signature']	= Buffer.from(@_sign(string2array(data['sdp'])))
					simple-peer::['emit'].call(@, 'signal', data)
				case 'data'
					if @_sending
						# Data are sent in alternating order, sending data when receiving is expected violates the protocol
						@'destroy'()
						return
					else if data.length != @_packet_size
						# Data size must be exactly one packet size
						@'destroy'()
						return
					else
						@_demultiplexer['feed'](data)
						while @_demultiplexer['have_more_data']()
							actual_data = @_demultiplexer['get_data']()
							command		= actual_data[0]
							if command == COMMAND_DHT
								simple-peer::['emit'].call(@, 'data', Buffer.from(actual_data.subarray(1)))
							else
								simple-peer::['emit'].call(@, 'routing_data', command, actual_data.subarray(1))
						@_sending	= true
						@_real_send()
				else
					simple-peer::['emit'].apply(@, &)
		/**
		 * @param {!Object} signal
		 */
		..'signal' = (signal) !->
			if !signal['signature'] || !signal['extensions']
				# Drop connection if signature or extensions not specified
				@'destroy'()
				return
			@_signature_received	= signal['signature']
			@_sdp_received			= string2array(signal['sdp'])
			found_psr				= false
			for extension in signal['extensions']
				if extension.startsWith('psr:')
					array						= extension.split(':')
					received_packet_size		= parseInt(array[1], 10)
					received_packets_per_second	= parseInt(array[2], 10)
					if received_packet_size < MIN_PACKET_SIZE || received_packets_per_second < 1
						@'destroy'()
						return
					@_packet_size			= Math.min(@_packet_size, received_packet_size)
					@_packets_per_second	= Math.min(@_packets_per_second, received_packets_per_second)
					found_psr				= true
					break
			if !found_psr
				@'destroy'()
				return
			simple-peer::['signal'].call(@, signal)
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {!Uint8Array} data
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
				if @'destroyed'
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
		shaObj['update'](data)
		Buffer.from(shaObj['getHash']('ARRAYBUFFER'))
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
	 * @param {!Uint8Array}		dht_public_key		Ed25519 public key, temporary one, just for DHT operation
	 * @param {!Uint8Array}		dht_private_key		Corresponding Ed25519 private key
	 * @param {!Array<!Object>}	bootstrap_nodes
	 * @param {!Array<!Object>}	ice_servers
	 * @param {number}			packet_size
	 * @param {number}			packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 *
	 * @return {!DHT}
	 *
	 * @throws {Error}
	 */
	!function DHT (dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size)
		if packet_size < MIN_PACKET_SIZE
			throw new Error('Minimal supported packet size is ' + MIN_PACKET_SIZE)
		async-eventer.call(@)
		if packets_per_second < 1
			packets_per_second	= 1
		@_pending_websocket_ids	= new Map
		extensions				= [
			"psr:#packet_size:#packets_per_second" # Packet size and rate
		]
		@_socket				= webrtc-socket(
			'extensions'				: extensions
			'simple_peer_constructor'	: simple-peer-detox
			'simple_peer_opts'		:
				'config'				:
					'iceServers'	: ice_servers
				'packet_size'			: packet_size
				'packets_per_second'	: packets_per_second
				'sign'					: (data) ->
					detox-crypto['sign'](data, dht_public_key, dht_private_key)
		)
			..'on'('websocket_peer_connection_alias', (websocket_host, websocket_port, peer_connection) !~>
				bootstrap_nodes.forEach (bootstrap_node) ~>
					if bootstrap_node.host != websocket_host || bootstrap_node.port != websocket_port
						return
					@_pending_websocket_ids.set(peer_connection, bootstrap_node['node_id'])
					peer_connection['on']('close', !~>
						@_pending_websocket_ids.delete(peer_connection)
					)
			)
			..'on'('node_connected', (string_id) !~>
				id				= hex2array(string_id)
				peer_connection	= @_socket['get_id_mapping'](string_id)
				# If connection was started from WebSocket (bootstrap node, insecure ws://), we need to confirm that WebRTC uses the same node ID as WebSocket
				if @_pending_websocket_ids.has(peer_connection)
					expected_id	= @_pending_websocket_ids.get(peer_connection)
					@_pending_websocket_ids.delete(peer_connection)
					if expected_id != string_id
						peer_connection['destroy']()
						return
				# Already Uint8Array, no need to convert SDP to array
				if !detox-crypto['verify'](peer_connection._signature_received, peer_connection._sdp_received, id)
					# Drop connection if node failed to sign SDP with its public message
					peer_connection['destroy']()
					return
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
		@_dht					= new webtorrent-dht(
			'bootstrap'		: bootstrap_nodes
			'extensions'	: extensions
			'hash'			: sha3_256
			'k'				: bucket_size
			'nodeId'		: Buffer.from(dht_public_key)
			'socket'		: @_socket
			'timeout'		: PEER_CONNECTION_TIMEOUT * 1000
			'verify'		: detox-crypto['verify']
		)
			..'on'('error', (error) !~>
				@'fire'('error', error)
			)
			..'once'('ready', !~>
				@'fire'('ready')
			)

	DHT:: = Object.create(async-eventer::)
	DHT::
		/**
		 * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
		 *
		 * @param {string}	ip
		 * @param {number}	port
		 */
		..'start_bootstrap_node' = (ip, port) !->
			@_dht['listen'](port, ip)
		/**
		 * Get an array of bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor
		 *
		 * @return {!Array<!Object>} Each element is an object with keys `host`, `port` and `node_id`
		 */
		..'get_bootstrap_nodes' = ->
			(
				for , peer_connection of @_dht['_rpc']['socket']['socket']['_peer_connections']
					if peer_connection['ws_server'] && peer_connection['id']
						{
							'node_id'	: peer_connection['id']
							'host'		: peer_connection['ws_server']['host']
							'port'		: peer_connection['ws_server']['port']
						}
			)
			.filter(Boolean)
		/**
		 * Start lookup for specified node ID (listen for `node_connected` in order to know when interested node was connected)
		 *
		 * @param {!Uint8Array} id
		 */
		..'lookup' = (id) !->
			@_dht['lookup'](Buffer.from(id))
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
			if data.length > @_packet_size
				return
			string_id		= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(data, COMMAND_DATA)
		/**
		 * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
		 *
		 * @param {!Uint8Array}			real_public_key		Ed25519 public key (real one, different from supplied in DHT constructor)
		 * @param {!Uint8Array}			real_private_key	Corresponding Ed25519 private key
		 * @param {!Array<!Uint8Array>}	introduction_nodes	Array of public keys of introduction points
		 *
		 * @return {!Object}
		 */
		..'generate_introduction_message' = (real_public_key, real_private_key, introduction_nodes) ->
			time	= +(new Date)
			value	= new Uint8Array(introduction_nodes.length * PUBLIC_KEY_LENGTH)
			for introduction_point, index in introduction_nodes
				value.set(introduction_point, index * PUBLIC_KEY_LENGTH)
			signature_data	= encode_signature_data(
				'seq'	: time
				'v'		: Buffer.from(value)
			)
			signature		= detox-crypto['sign'](signature_data, real_public_key, real_private_key)
			# This message has signature, so it can be now sent from any node in DHT
			{
				'k'		: real_public_key
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
				'seq'	: parseInt(message['seq'], 10)
				'sig'	: Buffer.from(message['sig'])
				'v'		: Buffer.from(message['v'])
			)
		/**
		 * Find nodes in DHT that are acting as introduction points for specified public key
		 *
		 * @param {!Uint8Array}	target_public_key
		 * @param {!Function}	success_callback
		 * @param {!Function}	failure_callback
		 */
		..'find_introduction_nodes' = (target_public_key, success_callback, failure_callback) !->
			hash	= sha3_256(target_public_key)
			@_dht['get'](hash, (, result) !->
				if !result || !result['v']
					# Nothing was found
					failure_callback()
					return
				introduction_nodes_bulk	= Uint8Array.from(result['v'])
				introduction_nodes		= []
				if introduction_nodes_bulk.length % PUBLIC_KEY_LENGTH != 0
					return
				for i from 0 til introduction_nodes_bulk.length / PUBLIC_KEY_LENGTH
					introduction_nodes.push(introduction_nodes_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH))
				success_callback(introduction_nodes)
			)
		/**
		 * Stop WebSocket server if running, close all active WebRTC connections
		 *
		 * @param {Function} callback
		 */
		..'destroy' = (callback) !->
			@_dht['destroy'](callback)
			delete @_dht
	Object.defineProperty(DHT::, 'constructor', {enumerable: false, value: DHT})
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}	dht_private_key			X25519 private key that corresponds to Ed25519 key used in `DHT` constructor
	 * @param {number}		packet_size				The same as in `DHT` constructor
	 * @param {number}		max_pending_segments	How much segments can be in pending state per one address
	 *
	 * @return {!Router}
	 *
	 * @throws {Error}
	 */
	!function Router (dht_private_key, packet_size, max_pending_segments = 10)
		if !(@ instanceof Router)
			return new Router(dht_private_key, packet_size, max_pending_segments)
		if packet_size < MIN_PACKET_SIZE
			throw new Error('Minimal supported packet size is ' + MIN_PACKET_SIZE)
		async-eventer.call(@)
		# Should be smaller than `packet_size` for DHT because it will be later sent through DHT's peer connection (2 bytes for multiplexer and 1 for command)
		packet_size					= packet_size - 3
		@_encryptor_instances		= new Map
		@_rewrapper_instances		= new Map
		@_last_node_in_routing_path	= new Map
		@_multiplexer				= new Map
		@_demultiplexer				= new Map
		@_established_routing_paths	= new Map
		@_ronion					= ronion(ROUTING_PROTOCOL_VERSION, packet_size, PUBLIC_KEY_LENGTH, MAC_LENGTH, max_pending_segments)
			.'on'('create_request', (data) !~>
				address			= data['address']
				segment_id		= data['segment_id']
				command_data	= data['command_data']
				source_id	= compute_source_id(address, segment_id)
				if @_encryptor_instances.has(source_id)
					# Something wrong is happening, refuse to handle
					return
				encryptor_instance	= detox-crypto['Encryptor'](false, dht_private_key)
				try
					encryptor_instance['put_handshake_message'](command_data)
				catch
					return
				@_ronion['create_response'](address, segment_id, encryptor_instance['get_handshake_message']())
				# At this point we simply assume that initiator received our response
				@_ronion['confirm_incoming_segment_established'](address, segment_id)
				@_multiplexer.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				@_demultiplexer.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				if !encryptor_instance['ready']()
					return
				rewrapper_instance					= encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
				address_string						= address.join(',')
				encryptor_instances					= Object.create(null)
				encryptor_instances[address_string]	= encryptor_instance
				rewrapper_instances					= Object.create(null)
				rewrapper_instances[address_string]	= rewrapper_instance
				@_encryptor_instances.set(source_id, encryptor_instances)
				@_rewrapper_instances.set(source_id, rewrapper_instances)
				@_last_node_in_routing_path.set(source_id, address)
			)
			.'on'('send', (data) !~>
				@'fire'('send', data['address'], data['packet'])
			)
			.'on'('data', (data) !~>
				address						= data['address']
				segment_id					= data['segment_id']
				target_address				= data['target_address']
				command_data				= data['command_data']
				source_id					= compute_source_id(address, segment_id)
				last_node_in_routing_path	= @_last_node_in_routing_path.get(source_id)
				if target_address.join(',') != last_node_in_routing_path.join(',')
					# We only accept data back from responder
					return
				demultiplexer				= @_demultiplexer.get(source_id)
				if !demultiplexer
					return
				demultiplexer['feed'](command_data)
				# Data are always more or equal to block size, so no need to do `while` loop
				if demultiplexer['have_more_data']()
					data	= demultiplexer['get_data']()
					@'fire'('data', address, segment_id, data)
			)
			.'on'('destroy', (data) !~>
				address		= data['address']
				segment_id	= data['segment_id']
				@_destroy_routing_path(address, segment_id)
				@'fire'('destroyed', address, segment_id)
			)
			.'on'('encrypt', (data) !~>
				address					= data['address']
				segment_id				= data['segment_id']
				target_address			= data['target_address']
				plaintext				= data['plaintext']
				source_id				= compute_source_id(address, segment_id)
				target_address_string	= target_address.join(',')
				encryptor_instance		= @_encryptor_instances.get(source_id)?[target_address_string]
				if !encryptor_instance
					return
				data['ciphertext']	= encryptor_instance['encrypt'](plaintext)
			)
			.'on'('decrypt', (data) !~>
				address					= data['address']
				segment_id				= data['segment_id']
				target_address			= data['target_address']
				ciphertext				= data['ciphertext']
				source_id				= compute_source_id(address, segment_id)
				target_address_string	= target_address.join(',')
				encryptor_instance		= @_encryptor_instances.get(source_id)?[target_address_string]
				if !encryptor_instance
					return
				# This can legitimately throw exceptions if ciphertext is not targeted at this node
				try
					data['plaintext']	= encryptor_instance['decrypt'](ciphertext)
			)
			.'on'('wrap', (data) !~>
				address					= data['address']
				segment_id				= data['segment_id']
				target_address			= data['target_address']
				unwrapped				= data['unwrapped']
				source_id				= compute_source_id(address, segment_id)
				target_address_string	= target_address.join(',')
				rewrapper_instance		= @_rewrapper_instances.get(source_id)?[target_address_string]?[0]
				if !rewrapper_instance
					return
				data['wrapped']	= rewrapper_instance['wrap'](unwrapped)
			)
			.'on'('unwrap', (data) !~>
				address					= data['address']
				segment_id				= data['segment_id']
				target_address			= data['target_address']
				wrapped					= data['wrapped']
				source_id				= compute_source_id(address, segment_id)
				target_address_string	= target_address.join(',')
				rewrapper_instance		= @_rewrapper_instances.get(source_id)?[target_address_string]?[1]
				if !rewrapper_instance
					return
				data['unwrapped']	= rewrapper_instance['unwrap'](wrapped)
			)
		@_max_packet_data_size	= @_ronion['get_max_command_data_length']()
	Router:: = Object.create(async-eventer::)
	Router::
		/**
		 * Process routing packet coming from node with specified ID
		 *
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} packet
		 */
		..'process_packet' = (node_id, packet) !->
			@_ronion['process_packet'](node_id, packet)
		/**
		 * Construct routing path through specified nodes
		 *
		 * @param {!Array<!Uint8Array>} nodes IDs of the nodes through which routing path must be constructed, last node in the list is responder
		 *
		 * @return {!Promise} Will resolve with ID of the route or will be rejected if path construction fails
		 */
		..'construct_routing_path' = (nodes) ->
			nodes	= nodes.slice() # Do not modify source array
			new Promise (resolve) !~>
				last_node_in_routing_path				= nodes[nodes.length - 1]
				first_node								= nodes.shift()
				first_node_string						= first_node.join(',')
				encryptor_instances						= Object.create(null)
				rewrapper_instances						= Object.create(null)
				fail									= !~>
					@_destroy_routing_path(first_node, route_id)
					throw new Error('Routing path creation failed')
				# Establishing first segment
				x25519_public_key						= detox-crypto['convert_public_key'](first_node)
				if !x25519_public_key
					fail()
				encryptor_instances[first_node_string]	= detox-crypto['Encryptor'](true, x25519_public_key)
				!~function create_response_handler (data)
					address			= data['address']
					segment_id		= data['segment_id']
					command_data	= data['command_data']
					if !is_string_equal_to_array(first_node_string, address) || !is_string_equal_to_array(route_id_string, segment_id)
						return
					clearTimeout(segment_establishment_timeout)
					@_ronion['off']('create_response', create_response_handler)
					try
						encryptor_instances[first_node_string]['put_handshake_message'](command_data)
					catch
						fail()
					if !encryptor_instances[first_node_string]['ready']()
						fail()
					rewrapper_instances[first_node_string]	= encryptor_instances[first_node_string]['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
					@_ronion['confirm_outgoing_segment_established'](first_node, route_id)
					@_multiplexer.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					@_demultiplexer.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					# Successfully established first segment, extending routing path further
					var current_node, current_node_string, segment_extension_timeout
					!~function extend_request
						if !nodes.length
							@_established_routing_paths.set(source_id, [first_node, route_id])
							resolve(route_id)
							return
						!~function extend_response_handler (data)
							address			= data['address']
							segment_id		= data['segment_id']
							command_data	= data['command_data']
							if !is_string_equal_to_array(first_node_string, address) || !is_string_equal_to_array(route_id_string, segment_id)
								return
							@_ronion.'off'('extend_response', extend_response_handler)
							clearTimeout(segment_extension_timeout)
							# If last node in routing path clearly said extension failed - no need to do something else here
							if !command_data.length
								fail()
							try
								encryptor_instances[current_node_string]['put_handshake_message'](command_data)
							catch
								fail()
							if !encryptor_instances[current_node_string]['ready']()
								fail()
							rewrapper_instances[current_node_string]	= encryptor_instances[current_node_string]['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
							@_ronion['confirm_extended_path'](first_node, route_id)
							# Successfully extended routing path by one more segment, continue extending routing path further
							extend_request()
						@_ronion['on']('extend_response', extend_response_handler)
						current_node								:= nodes.shift()
						current_node_string							:= current_node.join(',')
						x25519_public_key							= detox-crypto['convert_public_key'](current_node)
						if !x25519_public_key
							fail()
						encryptor_instances[current_node_string]	= detox-crypto['Encryptor'](true, x25519_public_key)
						segment_extension_timeout					:= setTimeout (!~>
							@_ronion['off']('extend_response', extend_response_handler)
							fail()
						), ROUTING_PATH_SEGMENT_TIMEOUT * 1000
						@_ronion['extend_request'](first_node, route_id, current_node, encryptor_instances[current_node_string]['get_handshake_message']())
					extend_request()
				@_ronion['on']('create_response', create_response_handler)
				segment_establishment_timeout	= setTimeout (!~>
					@_ronion['off']('create_response', create_response_handler)
					fail()
				), ROUTING_PATH_SEGMENT_TIMEOUT * 1000
				route_id						= @_ronion['create_request'](first_node, encryptor_instances[first_node_string]['get_handshake_message']())
				route_id_string					= route_id.join(',')
				source_id						= compute_source_id(first_node, route_id)
				@_encryptor_instances.set(source_id, encryptor_instances)
				@_rewrapper_instances.set(source_id, rewrapper_instances)
				@_last_node_in_routing_path.set(source_id, last_node_in_routing_path)
		/**
		 * Destroy routing path constructed earlier
		 *
		 * @param {!Uint8Array} node_id		First node in routing path
		 * @param {!Uint8Array} route_id	Identifier returned during routing path construction
		 */
		..'destroy_routing_path' = (node_id, route_id) !->
			@_destroy_routing_path(node_id, route_id)
		/**
		 * Send data to the responder on specified routing path
		 *
		 * @param {!Uint8Array} node_id		First node in routing path
		 * @param {!Uint8Array} route_id	Identifier returned during routing path construction
		 * @param {!Uint8Array} data
		 */
		..'send_data' = (node_id, route_id, data) !->
			if data.length > MAX_DATA_SIZE
				return
			source_id		= compute_source_id(node_id, route_id)
			target_address	= @_last_node_in_routing_path.get(source_id)
			multiplexer		= @_multiplexer.get(source_id)
			if !multiplexer
				return
			multiplexer['feed'](data)
			while multiplexer['have_more_blocks']()
				data_block	= multiplexer['get_block']()
				@_ronion['data'](node_id, route_id, target_address, data_block)
		/**
		 * Destroy all of the routing path constructed earlier
		 */
		..'destroy' = !->
			@_established_routing_paths.forEach ([address, segment_id]) !~>
				@_destroy_routing_path(address, segment_id)
		/**
		 * @param {!Uint8Array} address
		 * @param {!Uint8Array} segment_id
		 */
		.._destroy_routing_path = (address, segment_id) !->
			source_id			= compute_source_id(address, segment_id)
			encryptor_instances	= @_encryptor_instances.get(source_id)
			if !encryptor_instances
				return
			counter	= Object.keys(encryptor_instances).length
			!~function destroy_segment
				if counter
					--counter
					# When called from `destroy` event handler, calling `destroy()` method here will fail, but that is expected and is not a problem at all
					try
						@_ronion['destroy'](address, segment_id)
						# Let ronion send DESTROY command before destroying next segment and cleaning `Encryptor` instances
						@_ronion['once']('send', !~>
							destroy_segment()
						)
					catch
						destroy_segment()
				else
					for , encryptor_instance of encryptor_instances
						encryptor_instance['destroy']()
					@_encryptor_instances.delete(source_id)
					@_rewrapper_instances.delete(source_id)
					@_last_node_in_routing_path.delete(source_id)
					@_multiplexer.delete(source_id)
					@_demultiplexer.delete(source_id)
					@_established_routing_paths.delete(source_id)
			destroy_segment()
	Object.defineProperty(Router::, 'constructor', {enumerable: false, value: Router})
	{
		'ready'		: detox-crypto['ready']
		'DHT'		: DHT
		'Router'	: Router
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/dht', 'ronion', 'jssha/src/sha3', 'fixed-size-multiplexer', 'async-eventer'], Transport)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Transport(require('@detox/crypto'), require('@detox/dht'), require('ronion'), require('jssha/src/sha3'), require('fixed-size-multiplexer'), require('async-eventer'))
else
	# Browser globals
	@'detox_transport' = Transport(@'detox_crypto', @'detox_dht', @'ronion', @'jsSHA', @'fixed_size_multiplexer', @'async_eventer')
