/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
detox-crypto	= require('@detox/crypto')
lib				= require('..')
test			= require('tape')

bootstrap_ip	= '127.0.0.1'
bootstrap_port	= 16882

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

<-! lib.ready
test('DHT', (t) !->
	t.plan(16)

	bootstrap_node_dht	= detox-crypto.create_keypair(hex2array('561401dff7921304e6c266639cc6a37a14c1600f9928dbf9afc99a61f0732d43')) # ec63345e65cd1efa50816bf91d79e0e2302be7ddb4412b885cc69efe9a3b9e50
	node_1_dht			= detox-crypto.create_keypair(hex2array('4b39c9e51f2b644fd0678769cc53069e9c1a93984bbffd7f0fbca2375c08b815')) # ea977ae216d9de56a85a67f6a10cfd9e67d2b4ddb099892e0df937fa31c02ec0
	node_1_real			= detox-crypto.create_keypair(hex2array('cefed82d3c4e04af9c8ca516db37b48a09f602a7f11c565dc6707cfe2fa3373d')) # 6dcc9e14dc0377b0e1719999bc34ec8d077a5d0dd3494267f41163da01201432
	node_2_dht			= detox-crypto.create_keypair(hex2array('910e5d834e32835d427ca4507c4a6a6c1715fd7cbd290cda8d4c1aa90d0f251d')) # 3b0743c5da216e0171dbd42d6cf833cd5e50d39bf699c6c827639546376d3c0a
	node_3_dht			= detox-crypto.create_keypair(hex2array('7be95d9a4aecf3d353a5a9264b0c76497d977393d2b549f3cec51837f3b528e0')) # a9d27394df8cca4e7251f968867b26668467f3b4ea8f515386a7a4d8d30e7a45

	bootstrap_node_instance	= lib.DHT(bootstrap_node_dht.ed25519.public, bootstrap_node_dht.ed25519.private, [], [], 5, 2)
	bootstrap_node_instance.start_bootstrap_node(bootstrap_ip, bootstrap_port)

	bootstrap_node_info	= {
		node_id	: array2hex(bootstrap_node_dht.ed25519.public)
		host	: bootstrap_ip
		port	: bootstrap_port
	}

	node_1_instance	= lib.DHT(node_1_dht.ed25519.public, node_1_dht.ed25519.private, [bootstrap_node_info], [], 5, 2)
	node_2_instance	= lib.DHT(node_2_dht.ed25519.public, node_2_dht.ed25519.private, [bootstrap_node_info], [], 5, 2)
	node_3_instance	= lib.DHT(node_3_dht.ed25519.public, node_3_dht.ed25519.private, [bootstrap_node_info], [], 5, 2)

	wait_for	= 3
	!function ready
		--wait_for
		if !wait_for
			all_ready()
	node_1_instance.once('ready', ready)
	node_2_instance.once('ready', ready)
	node_3_instance.once('ready', ready)

	node_1_instance.once('node_connected', (node_id) !->
		t.equal(array2hex(node_id), array2hex(bootstrap_node_dht.ed25519.public), 'Connected to WebRTC (bootstrap) node #1')
	)
	node_2_instance.once('node_connected', (node_id) !->
		t.equal(array2hex(node_id), array2hex(bootstrap_node_dht.ed25519.public), 'Connected to WebRTC (bootstrap) node #2')
	)
	node_3_instance.once('node_connected', (node_id) !->
		t.equal(array2hex(node_id), array2hex(bootstrap_node_dht.ed25519.public), 'Connected to WebRTC (bootstrap) node #3')
	)

	function all_ready
		t.pass('Nodes are ready')

		t.deepEqual(node_1_instance.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly #1')
		t.deepEqual(node_2_instance.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly #2')
		t.deepEqual(node_3_instance.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly #3')

		introduction_nodes		= [
			detox-crypto.create_keypair().ed25519.public
			detox-crypto.create_keypair().ed25519.public
		]
		announcement_message	= node_1_instance.generate_announcement_message(node_1_real.ed25519.public, node_1_real.ed25519.private, introduction_nodes)

		node_1_instance._dht.on('put', !->
			# Just for robustness of test execution on Travis CI
			setTimeout !->
				node_3_instance.find_introduction_nodes(node_1_real.ed25519.public, (introduction_nodes_received) !->
					t.deepEqual(introduction_nodes_received, introduction_nodes, 'Introduction nodes found successfully')

					node_2_instance.once('node_tagged', (id) !->
						t.equal(array2hex(id), array2hex(node_1_dht.ed25519.public), 'Remote node tagged connection')

						node_2_instance.once('data', (id, command, data) !->
							t.equal(array2hex(id), array2hex(node_1_dht.ed25519.public), 'Received data from correct source')
							t.equal(command, 0, 'Received command is correct')
							t.equal(array2hex(data), array2hex(node_1_real.ed25519.public), 'Received correct data')

							node_2_instance.once('node_untagged', (id) !->
								t.equal(array2hex(id), array2hex(node_1_dht.ed25519.public), 'Remote node untagged connection')

								node_1_instance.once('node_disconnected', !->
									t.pass('Disconnected from WebRTC node #1')
								)
								node_2_instance.once('node_disconnected', !->
									t.pass('Disconnected from WebRTC node #2')
								)
								node_3_instance.once('node_disconnected', !->
									t.pass('Disconnected from WebRTC node #3')
								)

								bootstrap_node_instance.destroy()
								node_1_instance.destroy()
								node_2_instance.destroy()
								node_3_instance.destroy()
							)

							node_1_instance.del_used_tag(node_2_dht.ed25519.public)
						)
						node_1_instance.send_data(node_2_dht.ed25519.public, 0, node_1_real.ed25519.public)
					)
					node_1_instance.add_used_tag(node_2_dht.ed25519.public)
				)
		)

		node_2_instance.publish_announcement_message(announcement_message)
)
