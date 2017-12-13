// Generated by LiveScript 1.5.0
/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  var crypto, detoxCrypto, lib, test;
  crypto = require('crypto');
  detoxCrypto = require('@detox/crypto');
  lib = require('..');
  test = require('tape');
  /**
   * @param {!Uint8Array} array
   *
   * @return {string}
   */
  function array2hex(array){
    var string, i$, len$, byte;
    string = '';
    for (i$ = 0, len$ = array.length; i$ < len$; ++i$) {
      byte = array[i$];
      string += byte.toString(16).padStart(2, 0);
    }
    return string;
  }
  /**
   * @param {string} string
   *
   * @return {!Uint8Array}
   */
  function hex2array(string){
    var array, i$, to$, i;
    array = new Uint8Array(string.length / 2);
    for (i$ = 0, to$ = array.length; i$ < to$; ++i$) {
      i = i$;
      array[i] = parseInt(string.substring(i * 2, i * 2 + 2), 16);
    }
    return array;
  }
  lib.ready(function(){
    test('Router', function(t){
      var data, node_1, node_2, node_3, node_4, node_5, node_1_instance, node_2_instance, node_3_instance, node_4_instance, node_5_instance, nodes, ref$, i$, len$;
      t.plan(10);
      data = crypto.randomBytes(1000);
      node_1 = detoxCrypto.create_keypair(hex2array('4b39c9e51f2b644fd0678769cc53069e9c1a93984bbffd7f0fbca2375c08b815'));
      node_2 = detoxCrypto.create_keypair(hex2array('910e5d834e32835d427ca4507c4a6a6c1715fd7cbd290cda8d4c1aa90d0f251d'));
      node_3 = detoxCrypto.create_keypair(hex2array('7be95d9a4aecf3d353a5a9264b0c76497d977393d2b549f3cec51837f3b528e0'));
      node_4 = detoxCrypto.create_keypair(hex2array('561401dff7921304e6c266639cc6a37a14c1600f9928dbf9afc99a61f0732d43'));
      node_5 = detoxCrypto.create_keypair(hex2array('cefed82d3c4e04af9c8ca516db37b48a09f602a7f11c565dc6707cfe2fa3373d'));
      t.doesNotThrow(function(){
        node_1_instance = lib.Router(node_1.x25519['private'], 256, 20);
        node_2_instance = lib.Router(node_2.x25519['private'], 256, 20);
        node_3_instance = lib.Router(node_3.x25519['private'], 256, 20);
        node_4_instance = lib.Router(node_4.x25519['private'], 256, 20);
        node_5_instance = lib.Router(node_5.x25519['private'], 256, 20);
      }, 'Instance created without errors');
      nodes = (ref$ = {}, ref$[array2hex(node_1.ed25519['public'])] = node_1_instance, ref$[array2hex(node_2.ed25519['public'])] = node_2_instance, ref$[array2hex(node_3.ed25519['public'])] = node_3_instance, ref$[array2hex(node_4.ed25519['public'])] = node_4_instance, ref$[array2hex(node_5.ed25519['public'])] = node_5_instance, ref$);
      node_1_instance._public_key = node_1.ed25519['public'];
      node_2_instance._public_key = node_2.ed25519['public'];
      node_3_instance._public_key = node_3.ed25519['public'];
      node_4_instance._public_key = node_4.ed25519['public'];
      node_5_instance._public_key = node_5.ed25519['public'];
      global.node_1_instance = node_1_instance;
      global.node_2_instance = node_2_instance;
      global.node_3_instance = node_3_instance;
      global.node_4_instance = node_4_instance;
      global.node_5_instance = node_5_instance;
      for (i$ = 0, len$ = (ref$ = Object.values(nodes)).length; i$ < len$; ++i$) {
        (fn$.call(this, ref$[i$]));
      }
      node_1_instance.construct_routing_path([node_2.ed25519['public'], node_3.ed25519['public'], node_4.ed25519['public']]).then(function(route_id){
        var path_1;
        path_1 = {
          node_id: node_2.ed25519['public'],
          route_id: route_id
        };
        t.pass('Routing path created without errors #1 (1-2-3-4)');
        node_5_instance.construct_routing_path([node_3.ed25519['public'], node_4.ed25519['public'], node_2.ed25519['public'], node_1.ed25519['public']]).then(function(route_id){
          var path_5;
          path_5 = {
            node_id: node_3.ed25519['public'],
            route_id: route_id
          };
          t.pass('Routing path created without errors #2 (5-3-4-2-1)');
          node_4_instance.once('data', function(node_id, route_id, command, received_data){
            t.equal(array2hex(node_id), array2hex(node_3.ed25519['public']), 'Message from node 1 appears like it is coming from node 3');
            t.equal(command, 1, 'Command received correctly');
            t.equal(array2hex(data), array2hex(received_data), 'Data received correctly');
            node_1_instance.once('data', function(node_id, route_id, command, received_data){
              t.equal(array2hex(node_id), array2hex(path_1.node_id), 'Message to node 1 appears like it is coming from node 2');
              t.equal(command, 2, 'Command received correctly');
              t.equal(array2hex(data), array2hex(received_data), 'Data received correctly');
              node_1_instance.destroy();
              t.equal(node_1_instance._established_routing_paths.size, 0, 'Routing path on node 1 was destroyed properly');
            });
            node_4_instance.send_data(node_id, route_id, 2, data);
          });
          node_1_instance.send_data(path_1.node_id, path_1.route_id, 1, data);
        })['catch'](function(error){
          console.error(error);
          t.fail('Routing path created without errors #2 (5-3-4-2-1)');
        });
      })['catch'](function(error){
        console.error(error);
        t.fail('Routing path created without errors #1 (1-2-3-4)');
      });
      function fn$(node){
        node.on('send', function(node_id, packet){
          nodes[array2hex(node_id)].process_packet(node._public_key, packet);
        });
      }
    });
  });
}).call(this);
