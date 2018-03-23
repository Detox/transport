/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
const COMMAND_DHT				= 0
const COMMAND_TAG				= 1
const COMMAND_UNTAG				= 2
const CUSTOM_COMMANDS_OFFSET	= 10 # 3..9 are also reserved for future use, everything above is available for the user

# Length of Ed25519 public key in bytes
const PUBLIC_KEY_LENGTH				= 32
# ChaChaPoly+BLAKE2b
const MAC_LENGTH					= 16
# Max time in seconds allowed for routing path segment creation after which creation is considered failed
const ROUTING_PATH_SEGMENT_TIMEOUT	= 10
# 65 KiB is what is enough for DHT messages and will also be enough for routing data, bigger data will be multiplexed on higher levels when necessary
const MAX_DATA_SIZE					= 2 ** 16 - 1
# Fixed packet size for all DHT communications
const DHT_PACKET_SIZE				= 512
# 3 bytes (2 for multiplexer and 1 for command) smaller than packet size in DHT in order to avoid fragmentation when sending over peer connection
const ROUTER_PACKET_SIZE			= DHT_PACKET_SIZE - 3
# Same as in webtorrent-dht
const PEER_CONNECTION_TIMEOUT		= 30

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

function Wrapper (detox-crypto, detox-dht, detox-utils, ronion, fixed-size-multiplexer, async-eventer, pako)
	bencode				= detox-dht['bencode']
	simple-peer			= detox-dht['simple-peer']
	webrtc-socket		= detox-dht['webrtc-socket']
	webtorrent-dht		= detox-dht['webtorrent-dht']
	array2hex			= detox-utils['array2hex']
	hex2array			= detox-utils['hex2array']
	string2array		= detox-utils['string2array']
	are_arrays_equal	= detox-utils['are_arrays_equal']
	concat_arrays		= detox-utils['concat_arrays']
	ArrayMap			= detox-utils['ArrayMap']
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
		@_send_delay			= 1000 / options['packets_per_second']
		@_sending				= options['initiator']
		@_multiplexer			= fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, DHT_PACKET_SIZE)
		@_demultiplexer			= fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, DHT_PACKET_SIZE)
		@_send_zlib_buffer		= [new Uint8Array(0), new Uint8Array(0), new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)]
		@_receive_zlib_buffer	= [new Uint8Array(0), new Uint8Array(0), new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)]
		@'once'('connect', !~>
			@_last_sent	= +(new Date)
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
					data['signature']	= @_sign(string2array(data['sdp']))
					simple-peer::['emit'].call(@, 'signal', data)
				case 'data'
					if @_sending
						# Data are sent in alternating order, sending data when receiving is expected violates the protocol
						@'destroy'()
						return
					else if data.length != DHT_PACKET_SIZE
						# Data size must be exactly one packet size
						@'destroy'()
						return
					else
						@_demultiplexer['feed'](data)
						while @_demultiplexer['have_more_data']()
							actual_data = @_demultiplexer['get_data']()
							command		= actual_data[0]
							if command == COMMAND_DHT
								simple-peer::['emit'].call(@, 'data', @_zlib_decompress(actual_data.subarray(1)))
							else
								simple-peer::['emit'].call(@, 'custom_data', command, actual_data.subarray(1))
						@_sending	= true
						@_real_send()
				else
					simple-peer::['emit'].apply(@, &)
		/**
		 * @param {!Object} signal
		 */
		..'signal' = (signal) !->
			if !signal['signature']
				# Drop connection if signature not specified
				@'destroy'()
				return
			@_signature_received	= signal['signature']
			@_sdp_received			= string2array(signal['sdp'])
			# Connection might be closed already for some reason - catch thrown exception if that is the case
			try
				simple-peer::['signal'].call(@, signal)
		/**
		 * Data sending method that will be used by DHT
		 *
		 * @param {!Uint8Array} data
		 */
		..'send' = (data) !->
			@_send_multiplex(@_zlib_compress(data), COMMAND_DHT)
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
		/**
		 * @param {!Uint8Array} data
		 *
		 * @return {!Uint8Array}
		 */
		.._zlib_compress = (data) ->
			result	= pako['deflate'](data, {
				'dictionary'	: concat_arrays(@_send_zlib_buffer)
				'level'			: 1
			})
			update_dictionary_buffer(@_send_zlib_buffer, data)
			result
		/**
		 * @param {!Uint8Array} data
		 *
		 * @return {!Uint8Array}
		 */
		.._zlib_decompress = (data) ->
			result	= pako['inflate'](data, {
				'dictionary'	: concat_arrays(@_receive_zlib_buffer)
			})
			update_dictionary_buffer(@_receive_zlib_buffer, result)
			result

	Object.defineProperty(simple-peer-detox::, 'constructor', {value: simple-peer-detox})
	/**
	 * @param {!Uint8Array} data
	 *
	 * @return {!Uint8Array} Sometimes returns `Buffer` (depending on input type), but let's make Closure Compiler happy and specify `Uint8Array` for now
	 */
	function sha3_256 (data)
		# Hack: allows us to avoid using `Buffer` explicitly, but still return expected `Buffer`
		data.constructor['from'](
			detox-crypto['sha3_256'](data)
		)
	/**
	 * @param {!Object} message
	 *
	 * @return {!Uint8Array} Actually returns `Buffer`, but let's make Closure Compiler happy and specify `Uint8Array` for now
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
	 * @param {number}			packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
	 * @param {number}			bucket_size
	 *
	 * @return {!DHT}
	 */
	!function DHT (dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packets_per_second, bucket_size = 2)
		if !(@ instanceof DHT)
			return new DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packets_per_second, bucket_size)
		async-eventer.call(@)

		if packets_per_second < 1
			packets_per_second	= 1
		@_pending_websocket_ids	= new Map
		# This object is stored here, so that it can be updated if/when bootstrap node is started
		@_ws_address			= {}
		@_socket				= webrtc-socket(
			'simple_peer_constructor'	: simple-peer-detox
			'simple_peer_opts'			:
				'config'				:
					'iceServers'	: ice_servers
				'packets_per_second'	: packets_per_second
				'sign'					: (data) ->
					detox-crypto['sign'](data, dht_public_key, dht_private_key)
			'ws_address'				: @_ws_address
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
				peer_connection['on']('custom_data', (command, data) !~>
					switch command
						case COMMAND_TAG
							@_socket['add_tag'](string_id, 'detox-responder')
							@'fire'('node_tagged', id)
						case COMMAND_UNTAG
							@_socket['del_tag'](string_id, 'detox-responder')
							@'fire'('node_untagged', id)
						else
							if command < CUSTOM_COMMANDS_OFFSET
								return
							@'fire'('data', id, command - CUSTOM_COMMANDS_OFFSET, data)
				)
				@'fire'('node_connected', id)
			)
			..'on'('node_disconnected', (string_id) !~>
				@'fire'('node_disconnected', hex2array(string_id))
			)
		@_dht					= new webtorrent-dht(
			'bootstrap'		: bootstrap_nodes
			'hash'			: sha3_256
			'k'				: bucket_size
			'nodeId'		: dht_public_key
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
		 * @param {string}	address	Publicly available address that will be returned to other node, typically domain name (instead of using IP)
		 */
		..'start_bootstrap_node' = (ip, port, address = ip) !->
			if @_destroyed
				return
			Object.assign(@_ws_address, {
				'address'	: address
				'port'		: port
			})
			@_dht['listen'](port, ip)
		/**
		 * Get an array of bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor
		 *
		 * @return {!Array<!Object>} Each element is an object with keys `host`, `port` and `node_id`
		 */
		..'get_bootstrap_nodes' = ->
			if @_destroyed
				return []
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
			if @_destroyed
				return
			@_dht['lookup'](id)
		/**
		 * Tag connection to specified node ID as used, so that it is not disconnected when not used by DHT itself
		 *
		 * @param {!Uint8Array} id
		 */
		..'add_used_tag' = (id) !->
			if @_destroyed
				return
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
			if @_destroyed
				return
			string_id	= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(new Uint8Array(0), COMMAND_UNTAG)
				@_socket['del_tag'](string_id, 'detox-initiator')
		/**
		 * Send data to specified node ID
		 *
		 * @param {!Uint8Array}	id
		 * @param {number}		command	0..245
		 * @param {!Uint8Array}	data
		 */
		..'send_data' = (id, command, data) !->
			if @_destroyed || data.length > MAX_DATA_SIZE
				return
			string_id		= array2hex(id)
			peer_connection	= @_socket['get_id_mapping'](string_id)
			if peer_connection
				peer_connection._send_routing_data(data, command + CUSTOM_COMMANDS_OFFSET)
		/**
		 * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
		 *
		 * @param {!Uint8Array}			real_public_key		Ed25519 public key (real one, different from supplied in DHT constructor)
		 * @param {!Uint8Array}			real_private_key	Corresponding Ed25519 private key
		 * @param {!Array<!Uint8Array>}	introduction_nodes	Array of public keys of introduction points
		 *
		 * @return {!Uint8Array}
		 */
		..'generate_announcement_message' = (real_public_key, real_private_key, introduction_nodes) ->
			time	= +(new Date)
			value	= new Uint8Array(introduction_nodes.length * PUBLIC_KEY_LENGTH)
			for introduction_point, index in introduction_nodes
				value.set(introduction_point, index * PUBLIC_KEY_LENGTH)
			signature_data	= encode_signature_data(
				'seq'	: time
				'v'		: value
			)
			signature		= detox-crypto['sign'](signature_data, real_public_key, real_private_key)
			# This message has signature, so it can be now sent from any node in DHT
			Uint8Array.from(
				bencode['encode'](
					{
						'k'		: real_public_key
						'seq'	: time
						'sig'	: signature
						'v'		: value
					}
				)
			)
		/**
		 * @param {!Uint8Array} message
		 *
		 * @return {Uint8Array} Public key if signature is correct, `null` otherwise
		 */
		..'verify_announcement_message' = (message) ->
			try
				message	= bencode['decode'](message)
			if !message || !message['k'] || !message['seq'] || !message['sig'] || !message['v']
				return null
			signature_data	= encode_signature_data(
				'seq'	: message['seq']
				'v'		: message['v']
			)
			if detox-crypto['verify'](message['sig'], signature_data, message['k'])
				Uint8Array.from(message['k'])
			else
				null
		/**
		 * Publish message with introduction nodes (typically happens on different node than `generate_announcement_message()`)
		 *
		 * @param {!Uint8Array} message
		 */
		..'publish_announcement_message' = (message) !->
			if @_destroyed || !@'verify_announcement_message'(message)
				return
			@_dht['put'](bencode['decode'](message))
		/**
		 * Find nodes in DHT that are acting as introduction points for specified public key
		 *
		 * @param {!Uint8Array}	target_public_key
		 * @param {!Function}	success_callback
		 * @param {!Function}	failure_callback
		 */
		..'find_introduction_nodes' = (target_public_key, success_callback, failure_callback) !->
			if @_destroyed
				return
			hash	= sha3_256(target_public_key)
			@_dht['get'](hash, (, result) !->
				if !result || !result['v']
					# Nothing was found
					failure_callback?()
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
			if @_destroyed
				return
			@_dht['destroy'](callback)
			delete @_dht
			@_destroyed	= true
	Object.defineProperty(DHT::, 'constructor', {value: DHT})
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}	dht_private_key			X25519 private key that corresponds to Ed25519 key used in `DHT` constructor
	 * @param {number}		max_pending_segments	How much segments can be in pending state per one address
	 *
	 * @return {!Router}
	 *
	 * @throws {Error}
	 */
	!function Router (dht_private_key, max_pending_segments = 10)
		if !(@ instanceof Router)
			return new Router(dht_private_key, max_pending_segments)
		async-eventer.call(@)

		@_encryptor_instances		= ArrayMap()
		@_rewrapper_instances		= ArrayMap()
		@_last_node_in_routing_path	= ArrayMap()
		@_multiplexers				= ArrayMap()
		@_demultiplexers			= ArrayMap()
		@_established_routing_paths	= ArrayMap()
		@_ronion					= ronion(ROUTER_PACKET_SIZE, PUBLIC_KEY_LENGTH, MAC_LENGTH, max_pending_segments)
			.'on'('activity', (address, segment_id) !~>
				@'fire'('activity', address, segment_id)
			)
			.'on'('create_request', (address, segment_id, command_data) !~>
				if @_destroyed
					return
				source_id	= concat_arrays([address, segment_id])
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
				# Make sure each chunk after encryption will fit perfectly into DHT packet
				@_multiplexers.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				@_demultiplexers.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				if !encryptor_instance['ready']()
					return
				rewrapper_instance					= encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
				encryptor_instances					= ArrayMap()
				encryptor_instances.set(address, encryptor_instance)
				rewrapper_instances					= ArrayMap()
				rewrapper_instances.set(address, rewrapper_instance)
				@_encryptor_instances.set(source_id, encryptor_instances)
				@_rewrapper_instances.set(source_id, rewrapper_instances)
				@_last_node_in_routing_path.set(source_id, address)
			)
			.'on'('send', (address, packet) !~>
				@'fire'('send', address, packet)
			)
			.'on'('data', (address, segment_id, target_address, command, command_data) !~>
				if @_destroyed
					return
				source_id					= concat_arrays([address, segment_id])
				last_node_in_routing_path	= @_last_node_in_routing_path.get(source_id)
				if !are_arrays_equal(target_address, last_node_in_routing_path)
					# We only accept data back from responder
					return
				demultiplexer				= @_demultiplexers.get(source_id)
				if !demultiplexer
					return
				demultiplexer['feed'](command_data)
				# Data are always more or equal to block size, so no need to do `while` loop
				if demultiplexer['have_more_data']()
					data	= demultiplexer['get_data']()
					@'fire'('data', address, segment_id, command, data)
			)
			.'on'('encrypt', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				plaintext			= data['plaintext']
				source_id			= concat_arrays([address, segment_id])
				encryptor_instance	= @_encryptor_instances.get(source_id)?.get(target_address)
				if !encryptor_instance || !encryptor_instance['ready']()
					return
				data['ciphertext']	= encryptor_instance['encrypt'](plaintext)
			)
			.'on'('decrypt', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				ciphertext			= data['ciphertext']
				source_id			= concat_arrays([address, segment_id])
				encryptor_instance	= @_encryptor_instances.get(source_id)?.get(target_address)
				if !encryptor_instance || !encryptor_instance['ready']()
					return
				# This can legitimately throw exceptions if ciphertext is not targeted at this node
				try
					data['plaintext']	= encryptor_instance['decrypt'](ciphertext)
				catch
					/**
					 * Since we don't use all of Ronion features and only send data between initiator and responder, we can destroy unnecessary encryptor
					 * instances and don't even try to decrypt anything, which makes data forwarding less CPU intensive
					 */
					encryptor_instance['destroy']()
					@_encryptor_instances.get(source_id).delete(target_address)
			)
			.'on'('wrap', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				unwrapped			= data['unwrapped']
				source_id			= concat_arrays([address, segment_id])
				rewrapper_instance	= @_rewrapper_instances.get(source_id)?.get(target_address)?[0]
				if !rewrapper_instance
					return
				data['wrapped']	= rewrapper_instance['wrap'](unwrapped)
			)
			.'on'('unwrap', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				wrapped				= data['wrapped']
				source_id			= concat_arrays([address, segment_id])
				rewrapper_instance	= @_rewrapper_instances.get(source_id)?.get(target_address)?[1]
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
			if @_destroyed
				return
			@_ronion['process_packet'](node_id, packet)
		/**
		 * Construct routing path through specified nodes
		 *
		 * @param {!Array<!Uint8Array>} nodes IDs of the nodes through which routing path must be constructed, last node in the list is responder
		 *
		 * @return {!Promise} Will resolve with ID of the route or will be rejected if path construction fails
		 */
		..'construct_routing_path' = (nodes) ->
			if @_destroyed
				return Promise.reject()
			nodes	= nodes.slice() # Do not modify source array
			new Promise (resolve, reject) !~>
				last_node_in_routing_path				= nodes[* - 1]
				first_node								= nodes.shift()
				encryptor_instances						= ArrayMap()
				rewrapper_instances						= ArrayMap()
				fail									= !~>
					@_destroy_routing_path(first_node, route_id)
					reject('Routing path creation failed')
				# Establishing first segment
				x25519_public_key						= detox-crypto['convert_public_key'](first_node)
				if !x25519_public_key
					fail()
					return
				first_node_encryptor_instance			= detox-crypto['Encryptor'](true, x25519_public_key)
				encryptor_instances.set(first_node, first_node_encryptor_instance)
				!~function create_response_handler (address, segment_id, command_data)
					if !are_arrays_equal(first_node, address) || !are_arrays_equal(route_id, segment_id)
						return
					clearTimeout(segment_establishment_timeout)
					@_ronion['off']('create_response', create_response_handler)
					try
						first_node_encryptor_instance['put_handshake_message'](command_data)
					catch
						fail()
						return
					if !first_node_encryptor_instance['ready']()
						fail()
						return
					rewrapper_instances.set(
						first_node
						first_node_encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
					)
					@_ronion['confirm_outgoing_segment_established'](first_node, route_id)
					# Make sure each chunk after encryption will fit perfectly into DHT packet
					@_multiplexers.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					@_demultiplexers.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					# Successfully established first segment, extending routing path further
					var current_node, current_node_encryptor_instance, segment_extension_timeout
					!~function extend_request
						if !nodes.length
							@_established_routing_paths.set(source_id, [first_node, route_id])
							resolve(route_id)
							return
						!~function extend_response_handler (address, segment_id, command_data)
							if !are_arrays_equal(first_node, address) || !are_arrays_equal(route_id, segment_id)
								return
							@_ronion['off']('extend_response', extend_response_handler)
							clearTimeout(segment_extension_timeout)
							# If last node in routing path clearly said extension failed - no need to do something else here
							if !command_data.length
								fail()
								return
							try
								current_node_encryptor_instance['put_handshake_message'](command_data)
							catch
								fail()
								return
							if !current_node_encryptor_instance['ready']()
								fail()
								return
							rewrapper_instances.set(
								current_node
								current_node_encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
							)
							@_ronion['confirm_extended_path'](first_node, route_id)
							# Successfully extended routing path by one more segment, continue extending routing path further
							extend_request()
						@_ronion['on']('extend_response', extend_response_handler)
						current_node					:= nodes.shift()
						x25519_public_key				= detox-crypto['convert_public_key'](current_node)
						if !x25519_public_key
							fail()
							return
						current_node_encryptor_instance	:= detox-crypto['Encryptor'](true, x25519_public_key)
						encryptor_instances.set(current_node, current_node_encryptor_instance)
						segment_extension_timeout		:= setTimeout (!~>
							@_ronion['off']('extend_response', extend_response_handler)
							fail()
						), ROUTING_PATH_SEGMENT_TIMEOUT * 1000
						@_ronion['extend_request'](first_node, route_id, current_node, current_node_encryptor_instance['get_handshake_message']())
					extend_request()
				@_ronion['on']('create_response', create_response_handler)
				segment_establishment_timeout	= setTimeout (!~>
					@_ronion['off']('create_response', create_response_handler)
					fail()
				), ROUTING_PATH_SEGMENT_TIMEOUT * 1000
				route_id						= @_ronion['create_request'](first_node, first_node_encryptor_instance['get_handshake_message']())
				source_id						= concat_arrays([first_node, route_id])
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
		 * Max data size that will fit into single packet without fragmentation
		 *
		 * @return {number}
		 */
		..'get_max_packet_data_size' = ->
			@_max_packet_data_size
		/**
		 * Send data to the responder on specified routing path
		 *
		 * @param {!Uint8Array}	node_id		First node in routing path
		 * @param {!Uint8Array}	route_id	Identifier returned during routing path construction
		 * @param {number}		command		Command from range `0..245`
		 * @param {!Uint8Array}	data
		 */
		..'send_data' = (node_id, route_id, command, data) !->
			if @_destroyed
				return
			if data.length > MAX_DATA_SIZE
				return
			source_id		= concat_arrays([node_id, route_id])
			target_address	= @_last_node_in_routing_path.get(source_id)
			multiplexer		= @_multiplexers.get(source_id)
			if !multiplexer
				return
			multiplexer['feed'](data)
			while multiplexer['have_more_blocks']()
				data_block	= multiplexer['get_block']()
				@_ronion['data'](node_id, route_id, target_address, command, data_block)
		/**
		 * Destroy all of the routing path constructed earlier
		 */
		..'destroy' = !->
			if @_destroyed
				return
			@_destroyed = true
			@_established_routing_paths.forEach ([address, segment_id]) !~>
				@_destroy_routing_path(address, segment_id)
		/**
		 * @param {!Uint8Array} address
		 * @param {!Uint8Array} segment_id
		 */
		.._destroy_routing_path = (address, segment_id) !->
			source_id			= concat_arrays([address, segment_id])
			encryptor_instances	= @_encryptor_instances.get(source_id)
			if !encryptor_instances
				return
			encryptor_instances.forEach (encryptor_instance) !->
				encryptor_instance['destroy']()
			@_encryptor_instances.delete(source_id)
			@_rewrapper_instances.delete(source_id)
			@_last_node_in_routing_path.delete(source_id)
			@_multiplexers.delete(source_id)
			@_demultiplexers.delete(source_id)
			@_established_routing_paths.delete(source_id)
	Object.defineProperty(Router::, 'constructor', {value: Router})
	{
		'ready'			: detox-crypto['ready']
		'DHT'			: DHT
		'Router'		: Router
		'MAX_DATA_SIZE'	: MAX_DATA_SIZE
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/dht', '@detox/utils', 'ronion', 'fixed-size-multiplexer', 'async-eventer', 'pako'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/dht'), require('@detox/utils'), require('ronion'), require('fixed-size-multiplexer'), require('async-eventer'), require('pako'))
else
	# Browser globals
	@'detox_transport' = Wrapper(@'detox_crypto', @'detox_dht', @'detox_utils', @'ronion', @'fixed_size_multiplexer', @'async_eventer', @'pako')
