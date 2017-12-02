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
		string += byte.toString(16).padStart(2, 0)
	string

<-! lib.ready
test('DHT', (t) !->
	t.plan(3)

	bootstrap_node	= detox-crypto.create_keypair()
	node_1			= detox-crypto.create_keypair()
	node_2			= detox-crypto.create_keypair()

	bootstrap_node_instance	= lib.DHT(bootstrap_node.ed25519.public, bootstrap_node.ed25519.private, [], [], 512, 5, 2)
	bootstrap_node_instance.start_bootstrap_node(bootstrap_port, bootstrap_ip)

	bootstrap_node_info	= {
		node_id	: array2hex(bootstrap_node.ed25519.public)
		host	: bootstrap_ip
		port	: bootstrap_port
	}

	node_1_instance	= lib.DHT(node_1.ed25519.public, node_1.ed25519.private, [bootstrap_node_info], [], 512, 5, 2)
	node_2_instance	= lib.DHT(node_2.ed25519.public, node_2.ed25519.private, [bootstrap_node_info], [], 512, 5, 2)

	wait_for	= 2
	!function ready
		--wait_for
		if !wait_for
			all_ready()
	node_1_instance.once('ready', ready)
	node_2_instance.once('ready', ready)

	function all_ready
		t.pass('Nodes are ready')

		t.deepEqual(node_1_instance.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly #1')
		t.deepEqual(node_2_instance.get_bootstrap_nodes()[0], bootstrap_node_info, 'Bootstrap nodes are returned correctly #2')

		bootstrap_node_instance.destroy()
		node_1_instance.destroy()
		node_2_instance.destroy()
)
