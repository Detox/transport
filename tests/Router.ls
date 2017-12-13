/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
crypto			= require('crypto')
detox-crypto	= require('@detox/crypto')
lib				= require('..')
test			= require('tape')

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

<-! lib.ready
test('Router', (t) !->
	t.plan(10)

	data	= crypto.randomBytes(1000)
	node_1	= detox-crypto.create_keypair(hex2array('4b39c9e51f2b644fd0678769cc53069e9c1a93984bbffd7f0fbca2375c08b815')) # ea977ae216d9de56a85a67f6a10cfd9e67d2b4ddb099892e0df937fa31c02ec0
	node_2	= detox-crypto.create_keypair(hex2array('910e5d834e32835d427ca4507c4a6a6c1715fd7cbd290cda8d4c1aa90d0f251d')) # 3b0743c5da216e0171dbd42d6cf833cd5e50d39bf699c6c827639546376d3c0a
	node_3	= detox-crypto.create_keypair(hex2array('7be95d9a4aecf3d353a5a9264b0c76497d977393d2b549f3cec51837f3b528e0')) # a9d27394df8cca4e7251f968867b26668467f3b4ea8f515386a7a4d8d30e7a45
	node_4	= detox-crypto.create_keypair(hex2array('561401dff7921304e6c266639cc6a37a14c1600f9928dbf9afc99a61f0732d43')) # ec63345e65cd1efa50816bf91d79e0e2302be7ddb4412b885cc69efe9a3b9e50
	node_5	= detox-crypto.create_keypair(hex2array('cefed82d3c4e04af9c8ca516db37b48a09f602a7f11c565dc6707cfe2fa3373d')) # 6dcc9e14dc0377b0e1719999bc34ec8d077a5d0dd3494267f41163da01201432

	var node_1_instance, node_2_instance, node_3_instance, node_4_instance, node_5_instance
	t.doesNotThrow (!->
		node_1_instance	:= lib.Router(node_1.x25519.private, 256, 20)
		node_2_instance	:= lib.Router(node_2.x25519.private, 256, 20)
		node_3_instance	:= lib.Router(node_3.x25519.private, 256, 20)
		node_4_instance	:= lib.Router(node_4.x25519.private, 256, 20)
		node_5_instance	:= lib.Router(node_5.x25519.private, 256, 20)
	), 'Instance created without errors'

	nodes	=
		(array2hex(node_1.ed25519.public))	: node_1_instance
		(array2hex(node_2.ed25519.public))	: node_2_instance
		(array2hex(node_3.ed25519.public))	: node_3_instance
		(array2hex(node_4.ed25519.public))	: node_4_instance
		(array2hex(node_5.ed25519.public))	: node_5_instance

	node_1_instance._public_key	= node_1.ed25519.public
	node_2_instance._public_key	= node_2.ed25519.public
	node_3_instance._public_key	= node_3.ed25519.public
	node_4_instance._public_key	= node_4.ed25519.public
	node_5_instance._public_key	= node_5.ed25519.public

	global.node_1_instance = node_1_instance
	global.node_2_instance = node_2_instance
	global.node_3_instance = node_3_instance
	global.node_4_instance = node_4_instance
	global.node_5_instance = node_5_instance

	for let node in Object.values(nodes)
		node.on('send', (node_id, packet) !->
			nodes[array2hex(node_id)].process_packet(node._public_key, packet)
		)

	node_1_instance.construct_routing_path([node_2.ed25519.public, node_3.ed25519.public, node_4.ed25519.public])
		.then (route_id) !->
			path_1	=
				node_id		: node_2.ed25519.public
				route_id	: route_id

			t.pass('Routing path created without errors #1 (1-2-3-4)')


			node_5_instance.construct_routing_path([node_3.ed25519.public, node_4.ed25519.public, node_2.ed25519.public, node_1.ed25519.public])
				.then (route_id) !->
					path_5	=
						node_id		: node_3.ed25519.public
						route_id	: route_id

					t.pass('Routing path created without errors #2 (5-3-4-2-1)')

					node_4_instance.once('data', (node_id, route_id, command, received_data) !->
						t.equal(array2hex(node_id), array2hex(node_3.ed25519.public), 'Message from node 1 appears like it is coming from node 3')
						t.equal(command, 1, 'Command received correctly')
						t.equal(array2hex(data), array2hex(received_data), 'Data received correctly')

						node_1_instance.once('data', (node_id, route_id, command, received_data)!->
							t.equal(array2hex(node_id), array2hex(path_1.node_id), 'Message to node 1 appears like it is coming from node 2')
							t.equal(command, 2, 'Command received correctly')
							t.equal(array2hex(data), array2hex(received_data), 'Data received correctly')

							node_1_instance.destroy()
							t.equal(node_1_instance._established_routing_paths.size, 0, 'Routing path on node 1 was destroyed properly')
						)

						node_4_instance.send_data(node_id, route_id, 2, data)
					)

					node_1_instance.send_data(path_1.node_id, path_1.route_id, 1, data)
				.catch (error) !->
					console.error error
					t.fail('Routing path created without errors #2 (5-3-4-2-1)')
		.catch (error) !->
			console.error error
			t.fail('Routing path created without errors #1 (1-2-3-4)')
)
