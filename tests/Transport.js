// Generated by LiveScript 1.5.0
/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
(function(){
  var crypto, lib, test;
  crypto = require('crypto');
  lib = require('..');
  test = require('tape');
  test('Transport', function(t){
    var initiator_id, responder_unknown, responder_id, initiator_transport, responder_transport;
    t.plan(11);
    initiator_id = Buffer.from('foo');
    responder_unknown = Buffer.from('unknown');
    responder_id = Buffer.from('bar');
    initiator_transport = lib.Transport(initiator_id, [], 5, 10, 30);
    responder_transport = lib.Transport(responder_id, [], 5, 10, 30);
    initiator_transport.once('signal', function(peer_id, signal){
      t.same(peer_id, responder_unknown, 'Got signal for unknown responder');
      responder_transport.create_connection(false, initiator_id);
      responder_transport.signal(initiator_id, signal);
      responder_transport.once('signal', function(peer_id, signal){
        var connections, done;
        t.same(peer_id, initiator_id, 'Got signal for initiator');
        t.ok(initiator_transport.update_peer_id(responder_unknown, responder_id), 'Responder ID update succeeded');
        initiator_transport.signal(responder_id, signal);
        connections = 0;
        done = false;
        function connected(){
          var generated_command, generated_data;
          ++connections;
          t.pass('Connected #' + connections);
          if (connections === 2) {
            generated_command = 5;
            generated_data = crypto.randomBytes(20);
            initiator_transport.send(responder_id, generated_command, generated_data);
            responder_transport.once('data', function(arg$, command, data){
              t.equal(command, generated_command, 'Got correct command from initiator');
              t.equal(data.length, generated_data.length, 'Got correct data length from initiator');
              t.same(Buffer.from(data), generated_data, 'Got correct data from initiator');
              generated_command = 25;
              generated_data = crypto.randomBytes(20);
              responder_transport.send(initiator_id, generated_command, generated_data);
              initiator_transport.once('data', function(arg$, command, data){
                t.equal(command, generated_command, 'Got correct command from responder');
                t.equal(data.length, generated_data.length, 'Got correct data length from responder');
                t.same(Buffer.from(data), generated_data, 'Got correct data from responder');
                done = true;
                initiator_transport.destroy();
                responder_transport.destroy();
              });
            });
          }
        }
        initiator_transport.on('connected', connected).on('disconnected', function(){
          t.fail('Disconnected');
        });
        responder_transport.on('connected', connected).on('disconnected', function(){
          t.fail('Disconnected');
        });
      });
    }).create_connection(true, responder_unknown);
  });
  test('Transport: concurrent connections initialization', function(t){
    var initiator_id, responder_id, initiator_transport, responder_transport, connections;
    t.plan(4);
    initiator_id = Buffer.from('foo');
    responder_id = Buffer.from('bar');
    initiator_transport = lib.Transport(initiator_id, [], 5, 10, 30);
    responder_transport = lib.Transport(responder_id, [], 5, 10, 30);
    connections = 0;
    function connected(){
      ++connections;
      t.pass('Connected #' + connections);
      if (connections === 2) {
        initiator_transport.destroy();
        responder_transport.destroy();
      }
    }
    initiator_transport.on('signal', function(peer_id, signal){
      t.same(peer_id, responder_id, 'Got signal for responder');
      responder_transport.signal(initiator_id, signal);
    }).on('connected', connected).on('disconnected', function(){
      t.fail('Disconnected');
    }).create_connection(true, responder_id);
    responder_transport.on('signal', function(peer_id, signal){
      t.same(peer_id, initiator_id, 'Got signal for initiator');
      initiator_transport.signal(responder_id, signal);
    }).on('connected', connected).on('disconnected', function(){
      t.fail('Disconnected');
    }).create_connection(true, initiator_id);
  });
}).call(this);
