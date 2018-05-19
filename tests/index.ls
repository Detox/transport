/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
crypto	= require('crypto')
lib		= require('..')
test	= require('tape')

test('Transport', (t) !->
	t.plan(12)

	done		= false
	initiator	= lib.P2P_transport(true, [], 1000)
		.on('connected', !->
			t.pass('Initiator connected successfully')

			generated_command	= 5
			generated_data		= crypto.randomBytes(lib.MAX_COMPRESSED_DATA_SIZE)
			responder.once('data', (command, data) !->
				t.equal(command, generated_command, 'Got correct command from initiator')
				t.equal(data.length, generated_data.length, 'Got correct data length from initiator')
				t.same(Buffer.from(data), generated_data, 'Got correct data from initiator')

				generated_command	:= 25
				generated_data		:= crypto.randomBytes(lib.MAX_DATA_SIZE)
				initiator.once('data', (command, data) !->
					t.equal(command, generated_command, 'Got correct command from responder')
					t.equal(data.length, generated_data.length, 'Got correct data length from responder')
					t.same(Buffer.from(data), generated_data, 'Got correct data from responder')

					done := true
					initiator.destroy()
				)
				responder.send(generated_command, generated_data)
			)
			initiator.send(generated_command, generated_data)
		)
		.on('disconnected', !->
			t.ok(done, 'Initiator disconnected after done')
		)
	responder	= lib.P2P_transport(false, [], 1000)
		.on('connected', !->
			t.pass('Responder connected successfully')
		)
		.on('disconnected', !->
			t.ok(done, 'Responder disconnected after done')
		)
	initiator.get_signal()
		.then (signal) !->
			t.pass('Getting signal succeeded on initiator')
			responder.set_signal(signal)
		.catch !->
			t.fail('Getting signal failed on initiator')
	responder.get_signal()
		.then (signal) !->
			t.pass('Getting signal succeeded on responder')
			initiator.set_signal(signal)
		.catch !->
			t.fail('Getting signal failed on responder')
)
