// Generated by LiveScript 1.5.0
/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  function Transport(webtorrentDht, ronion, jssha, asyncEventer){
    var webrtcSocket, simplePeer, x$, y$, z$;
    webrtcSocket = webtorrentDht({
      bootstrap: []
    })._rpc.socket.socket;
    simplePeer = webrtcSocket._simple_peer_constructor;
    /**
     * @constructor
     *
     * @param {!Array} options
     */
    function webrtcSocketDetox(options){
      if (!(this instanceof webrtcSocketDetox)) {
        return new webrtcSocketDetox(options);
      }
      webrtcSocket.call(this, options);
    }
    webrtcSocketDetox.prototype = Object.create(webrtcSocket.prototype);
    x$ = webrtcSocketDetox.prototype;
    /**
     * We'll reuse single WebRTC connection for both DHT and anonymous routing,
     * so we don't want to immediately disconnect from the node as soon as it is not used by DHT
     *
     * @param {string} id
     */
    x$.del_id_mapping = function(id){
      var peer_connection;
      peer_connection = this.get_id_mapping(id);
      if (peer_connection.connected && !peer_connection.destroyed && peer_connection._used_by_detox) {
        return;
      }
      webrtcSocket.prototype.del_id_mapping(id);
    };
    Object.defineProperty(webrtcSocketDetox.prototype, 'constructor', {
      enumerable: false,
      value: webrtcSocketDetox
    });
    /**
     * We'll authenticate remove peers by requiring them to sign SDP by their DHT key
     * TODO: ^ is not implemented yet
     *
     * @constructor
     *
     * @param {!Array} options
     */
    function simplePeerDetox(options){
      if (!(this instanceof simplePeerDetox)) {
        return new simplePeerDetox(options);
      }
      simplePeer.call(this, options);
    }
    simplePeerDetox.prototype = Object.create(simplePeer.prototype);
    y$ = simplePeerDetox.prototype;
    /**
     * Dirty hack to get `data` event and handle it the way we want
     */
    y$.emit = function(event, data){
      if (event === 'data') {
        if (data[0] === 1) {
          simplePeer.prototype.emit.call(this, 'data', data.subarray(1));
        } else {
          simplePeer.prototype.emit.call(this, 'routing_data', data.subarray(1));
        }
      } else {
        simplePeer.prototype.emit.apply(this, arguments);
      }
    };
    /**
     * Data sending method that will be used by DHT
     *
     * @param {Buffer} data
     */
    y$.send = function(data){
      this.real_send(data, true);
    };
    /**
     * Data sending method that will be used by anonymous routing
     *
     * @param {Uint8Array} data
     */
    y$.send_routing_data = function(data){
      this.real_send(data, false);
    };
    /**
     * Actual data sending method moved here
     *
     * @param {Uint8Array}	data
     * @param {boolean}		for_dht	Whether data sent are for DHT or not
     */
    y$.real_send = function(data, for_dht){
      var x$, data_with_header;
      x$ = data_with_header = new Uint8Array(data.length + 1);
      x$.set([for_dht ? 1 : 0]);
      x$.set(data, 1);
      simplePeer.prototype.send.call(this, data_with_header);
    };
    Object.defineProperty(simplePeerDetox.prototype, 'constructor', {
      enumerable: false,
      value: simplePeerDetox
    });
    /**
     * @param {!Uint8Array} data
     *
     * @return {string}
     */
    function sha3_256(data){
      var shaObj;
      shaObj = new jsSHA('SHA3-256', 'ARRAYBUFFER');
      shaObj.update(array);
      return shaObj.getHash('HEX');
    }
    /**
     * @constructor
     *
     * @param {!Uint8Array}	node_id
     * @param {!string[]}	bootstrap_nodes
     * @param {!Object[]}	ice_servers
     * @param {number}		bucket_size
     *
     * @return {DHT}
     */
    function DHT(node_id, bootstrap_nodes, ice_servers, bucket_size){
      var socket, x$, this$ = this;
      bucket_size == null && (bucket_size = 2);
      if (!(this instanceof DHT)) {
        return new DHT(node_id, bootstrap_nodes, ice_servers, bucket_size);
      }
      asyncEventer.call(this);
      socket = webrtcSocketDetox({
        simple_peer_constructor: simplePeerDetox,
        simple_peer_opts: {
          config: {
            iceServers: ice_servers
          }
        }
      });
      x$ = socket;
      x$.on('node_connected', function(id){
        this$.fire('node_connected', id);
      });
      x$.on('node_disconnected', function(id){
        this$.fire('node_disconnected', id);
      });
      this._dht = new DHT({
        bootstrap: bootstrap_nodes,
        hash: sha3_256,
        k: bucket_size,
        nodeId: node_id,
        socket: socket
      });
    }
    DHT.prototype = Object.create(asyncEventer.prototype);
    z$ = DHT.prototype;
    /**
     * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
     *
     * @param {number}	port
     * @param {string}	ip
     */
    z$['start_bootstrap_node'] = function(port, ip){
      this._dht.listen(port, ip);
    };
    /**
     * @return {!string[]}
     */
    z$['get_bootstrap_nodes'] = function(){
      return this._dht.toJSON().nodes;
    };
    /**
     * @param {Function} callback
     */
    z$['destroy'] = function(callback){
      this._dht.destroy(callback);
      delete this._dht;
    };
    Object.defineProperty(DHT.prototype, 'constructor', {
      enumerable: false,
      value: DHT
    });
    return {
      'DHT': DHT
    };
  }
  if (typeof define === 'function' && define['amd']) {
    define(['webtorrent-dht', 'ronion', 'jssha/src/sha3', 'async-eventer'], Transport);
  } else if (typeof exports === 'object') {
    module.exports = Transport(require('webtorrent-dht'), require('ronion'), require('jssha/src/sha3'), require('async-eventer'));
  } else {
    this['detox_transport'] = Transport(this['webtorrent_dht'], this['ronion'], this['jsSHA'], this['async_eventer']);
  }
}).call(this);
