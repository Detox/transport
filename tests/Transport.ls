/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
crypto	= require('crypto')
lib		= require('..')
test	= require('tape')

test('Transport', (t) !->
	t.plan(11)

	initiator_id		= Buffer.from('foo')
	responder_unknown	= Buffer.from('unknown')
	responder_id		= Buffer.from('bar')
	initiator_transport	= lib.Transport(initiator_id, [], 5, 10, 30)
	responder_transport	= lib.Transport(responder_id, [], 5, 10, 30)
	initiator_transport
		.once('signal', (peer_id, signal) !->
			t.same(peer_id, responder_unknown, 'Got signal for unknown responder')

			responder_transport.create_connection(false, initiator_id)
			responder_transport.signal(initiator_id, signal)
			responder_transport.once('signal', (peer_id, signal) !->
				t.same(peer_id, initiator_id, 'Got signal for initiator')

				t.ok(initiator_transport.update_peer_id(responder_unknown, responder_id), 'Responder ID update succeeded')
				initiator_transport.signal(responder_id, signal)
				connections	= 0
				done		= false
				!function connected
					++connections
					t.pass('Connected #' + connections)

					if connections == 2
						generated_command	= 5
						generated_data		= crypto.randomBytes(20)
						initiator_transport.send(responder_id, generated_command, generated_data)
						responder_transport.once('data', (, command, data) !->
							t.equal(command, generated_command, 'Got correct command from initiator')
							t.equal(data.length, generated_data.length, 'Got correct data length from initiator')
							t.same(Buffer.from(data), generated_data, 'Got correct data from initiator')

							generated_command	:= 25
							generated_data		:= crypto.randomBytes(20)
							responder_transport.send(initiator_id, generated_command, generated_data)
							initiator_transport.once('data', (, command, data) !->
								t.equal(command, generated_command, 'Got correct command from responder')
								t.equal(data.length, generated_data.length, 'Got correct data length from responder')
								t.same(Buffer.from(data), generated_data, 'Got correct data from responder')

								done := true
								initiator_transport.destroy()
								responder_transport.destroy()
							)
						)

				initiator_transport
					.on('connected', connected)
					.on('disconnected', !->
						t.fail('Disconnected')
					)
				responder_transport
					.on('connected', connected)
					.on('disconnected', !->
						t.fail('Disconnected')
					)
			)
		)
		.create_connection(true, responder_unknown)
)
