// Generated by LiveScript 1.5.0
/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  var COMMAND_DHT, COMMAND_DATA, COMMAND_TAG, COMMAND_UNTAG, ROUTING_PROTOCOL_VERSION, PUBLIC_KEY_LENGTH, MAC_LENGTH, MIN_PACKET_SIZE;
  COMMAND_DHT = 0;
  COMMAND_DATA = 1;
  COMMAND_TAG = 2;
  COMMAND_UNTAG = 3;
  ROUTING_PROTOCOL_VERSION = 0;
  PUBLIC_KEY_LENGTH = 32;
  MAC_LENGTH = 16;
  MIN_PACKET_SIZE = 256;
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
  /**
   * @param {string} string
   *
   * @return {!Uint8Array}
   */
  function string2array(string){
    var array, i$, to$, i;
    array = new Uint8Array(string.length);
    for (i$ = 0, to$ = string.length; i$ < to$; ++i$) {
      i = i$;
      array[i] = string.charCodeAt(i);
    }
    return array;
  }
  /**
   * @interface
   *
   * Public and private key are implicitly assumed to correspond to current node's ones
   *
   * @param {!Uint8Array} data
   * @param {!Uint8Array} public_key
   * @param {!Uint8Array} private_key
   *
   * @return {!Uint8Array} Signature
   */
  function sign(data, public_key, private_key){}
  /**
   * @interface
   *
   * @param {!Uint8Array} signature
   * @param {!Uint8Array} data
   * @param {!Uint8Array} public_key	Ed25519 public key
   *
   * @return {boolean}
   */
  function verify(signature, data, public_key){}
  /**
   * @interface
   *
   * @param {!Uint8Array[]} introduction_points
   */
  function found_introduction_points(introduction_points){}
  function Transport(detoxDht, ronion, jssha, fixedSizeMultiplexer, asyncEventer){
    var simplePeer, webrtcSocket, webtorrentDht, Buffer, x$, y$;
    simplePeer = detoxDht['simple-peer'];
    webrtcSocket = detoxDht['webrtc-socket'];
    webtorrentDht = detoxDht['webtorrent-dht'];
    Buffer = detoxDht['Buffer'];
    /**
     * We'll authenticate remove peers by requiring them to sign SDP by their DHT key
     *
     * @constructor
     *
     * @param {!Object} options
     */
    function simplePeerDetox(options){
      var this$ = this;
      if (!(this instanceof simplePeerDetox)) {
        return new simplePeerDetox(options);
      }
      this._sign = options.sign;
      this._packet_size = options.packet_size;
      this._packets_per_second = options.packets_per_second;
      this._sending = options.initiator;
      this['once']('connect', function(){
        this$._send_delay = 1000 / this$._packets_per_second;
        this$._multiplexer = fixedSizeMultiplexer['Multiplexer'](this$._packet_size, this$._packet_size);
        this$._demultiplexer = fixedSizeMultiplexer['Demultiplexer'](this$._packet_size, this$._packet_size);
        this$._last_sent = +new Date;
        if (this$._sending) {
          this$._real_send();
        }
      });
      simplePeer.call(this, options);
    }
    simplePeerDetox.prototype = Object.create(simplePeer.prototype);
    x$ = simplePeerDetox.prototype;
    /**
     * Dirty hack to get `data` event and handle it the way we want
     */
    x$['emit'] = function(event, data){
      var actual_data, command;
      switch (event) {
      case 'signal':
        data.signature = this._sign(string2array(data['sdp']));
        simplePeer.prototype['emit'].call(this, 'signal', data);
        break;
      case 'data':
        if (this._sending) {
          this['destroy']();
          return;
        } else if (data.length !== this._packet_size) {
          return;
        } else {
          this._demultiplexer['feed'](data);
          if (this._demultiplexer['have_more_data']()) {
            /**
             * @type {!Uint8Array}
             */
            actual_data = this._demultiplexer['get_data']();
            command = actual_data[0];
            if (command === COMMAND_DHT) {
              simplePeer.prototype['emit'].call(this, 'data', actual_data.subarray(1));
            } else {
              simplePeer.prototype['emit'].call(this, 'routing_data', command, actual_data.subarray(1));
            }
          }
          this._sending = true;
          this._real_send();
        }
        break;
      default:
        simplePeer.prototype['emit'].apply(this, arguments);
      }
    };
    /**
     * @param {!Object} signal
     */
    x$['signal'] = function(signal){
      var found_psr, i$, ref$, len$, extension, array, received_packet_size, received_packets_per_second;
      if (!signal.signature || !!signal['extensions']) {
        this['destroy']();
        return;
      }
      this._signature_received = signal.signature;
      this._sdp_received = signal['sdp'];
      found_psr = false;
      for (i$ = 0, len$ = (ref$ = signal['extensions']).length; i$ < len$; ++i$) {
        extension = ref$[i$];
        if (extension.startsWith('psr:')) {
          array = extension.split(':');
          received_packet_size = parseInt(array[1]);
          received_packets_per_second = parseInt(array[2]);
          if (received_packet_size < 1 || received_packets_per_second < 1) {
            this['destroy']();
            return;
          }
          this._packet_size = Math.min(this._packet_size, received_packet_size);
          this._packets_per_second = Math.min(this._packets_per_second, received_packets_per_second);
          found_psr = true;
          break;
        }
      }
      if (!found_psr) {
        this['destroy']();
        return;
      }
      simplePeer.prototype['emit'].call(this, signal);
    };
    /**
     * Data sending method that will be used by DHT
     *
     * @param {Buffer} data
     */
    x$['send'] = function(data){
      this._send_multiplex(data, COMMAND_DHT);
    };
    /**
     * Data sending method that will be used by anonymous routing
     *
     * @param {!Uint8Array}	data
     * @param {number}		command 1..255 - routing data command being sent
     */
    x$._send_routing_data = function(data, command){
      this._send_multiplex(data, command);
    };
    /**
     * Actual data sending method moved here
     *
     * @param {!Uint8Array}	data
     * @param {number}		command
     */
    x$._send_multiplex = function(data, command){
      var x$, data_with_header;
      x$ = data_with_header = new Uint8Array(data.length + 1);
      x$.set([command]);
      x$.set(data, 1);
      this._multiplexer['feed'](data_with_header);
    };
    /**
     * Send a block of multiplexed data to the other side
     */
    x$._real_send = function(){
      var delay, this$ = this;
      delay = Math.max(0, this._send_delay - (new Date - this._last_sent));
      setTimeout(function(){
        if (this$._destroyed) {
          return;
        }
        simplePeer.prototype['send'].call(this$, this$._multiplexer['get_block']());
        this$._sending = false;
        this$._last_sent = +new Date;
      }, delay);
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
      shaObj['update'](array);
      return shaObj['getHash']('HEX');
    }
    /**
     * @param {!Object} message
     *
     * @return {!Buffer}
     */
    function encode_signature_data(message){
      return bencode['encode'](message).slice(1, -1);
    }
    /**
     * @constructor
     *
     * @param {!Uint8Array}	dht_public_key		Ed25519 public key, temporary one, just for DHT operation
     * @param {!Uint8Array}	dht_private_key		Corresponding Ed25519 private key
     * @param {string[]}	bootstrap_nodes
     * @param {!Object[]}	ice_servers
     * @param {!sign}		sign
     * @param {!verify}		verify
     * @param {number}		packet_size
     * @param {number}		packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
     * @param {number}		bucket_size
     *
     * @return {!DHT}
     *
     * @throws {Error}
     */
    function DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, sign, verify, packet_size, packets_per_second, bucket_size){
      var x$, this$ = this;
      bucket_size == null && (bucket_size = 2);
      if (!(this instanceof DHT)) {
        return new DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, sign, verify, packet_size, packets_per_second, bucket_size);
      }
      if (packet_size < MIN_PACKET_SIZE) {
        throw new Error('Minimal supported packet size is ' + MIN_PACKET_SIZE);
      }
      asyncEventer.call(this);
      if (packets_per_second < 1) {
        packets_per_second = 1;
      }
      this._sign = sign;
      this._socket = webrtcSocket({
        'simple_peer_constructor': simplePeerDetox,
        'simple_peer_opts': {
          'config': {
            'iceServers': ice_servers
          },
          'packet_size': packet_size,
          'packets_per_second': packets_per_second,
          'sign': function(data){
            return sign(data, dht_public_key, dht_private_key);
          }
        }
      });
      x$ = this._socket;
      x$['on']('node_connected', function(string_id){
        var id, peer_connection;
        id = hex2array(string_id);
        peer_connection = this$._socket['get_id_mapping'](string_id);
        if (!verify(peer_connection._signature_received, peer_connection._sdp_received, id)) {
          peer_connection['destroy']();
        }
        peer_connection['on']('routing_data', function(command, data){
          switch (command) {
          case COMMAND_TAG:
            this$._socket['add_tag'](string_id, 'detox-responder');
            this$['fire']('node_tagged', id);
            break;
          case COMMAND_UNTAG:
            this$._socket['del_tag'](string_id, 'detox-responder');
            this$['fire']('node_untagged', id);
            break;
          case COMMAND_DATA:
            this$['fire']('data', id, data);
          }
        });
        this$['fire']('node_connected', id);
      });
      x$['on']('node_disconnected', function(string_id){
        this$['fire']('node_disconnected', hex2array(string_id));
      });
      this._dht = new webtorrentDht({
        'bootstrap': bootstrap_nodes,
        'extensions': ["psr:" + packet_size + ":" + packets_per_second],
        'hash': sha3_256,
        'k': bucket_size,
        'nodeId': dht_public_key,
        'socket': this._socket,
        'verify': verify
      });
    }
    DHT.prototype = Object.create(asyncEventer.prototype);
    y$ = DHT.prototype;
    /**
     * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
     *
     * @param {number}	port
     * @param {string}	ip
     */
    y$['start_bootstrap_node'] = function(port, ip){
      this._dht.listen(port, ip);
    };
    /**
     * @return {!string[]}
     */
    y$['get_bootstrap_nodes'] = function(){
      return this._dht.toJSON().nodes;
    };
    /**
     * Start lookup for specified node ID (listen for `node_connected` in order to know when interested node was connected)
     *
     * @param {!Uint8Array} id
     */
    y$['lookup'] = function(id){
      this._dht.lookup(array2hex(id));
    };
    /**
     * Tag connection to specified node ID as used, so that it is not disconnected when not used by DHT itself
     *
     * @param {!Uint8Array} id
     */
    y$['add_used_tag'] = function(id){
      var string_id, peer_connection;
      string_id = array2hex(id);
      peer_connection = this._socket['get_id_mapping'](string_id);
      if (peer_connection) {
        peer_connection._send_routing_data(new Uint8Array(0), COMMAND_TAG);
        this._socket['add_tag'](string_id, 'detox-initiator');
      }
    };
    /**
     * Remove tag from connection, so that it can be disconnected if not needed by DHT anymore
     *
     * @param {!Uint8Array} id
     */
    y$['del_used_tag'] = function(id){
      var string_id, peer_connection;
      string_id = array2hex(id);
      peer_connection = this._socket['get_id_mapping'](string_id);
      if (peer_connection) {
        peer_connection._send_routing_data(new Uint8Array(0), COMMAND_UNTAG);
        this._socket['del_tag'](string_id, 'detox-initiator');
      }
    };
    /**
     * Send data to specified node ID
     *
     * @param {!Uint8Array} id
     * @param {!Uint8Array} data
     */
    y$['send_data'] = function(id, data){
      var string_id, peer_connection;
      if (data.length > this._packet_size) {
        return;
      }
      string_id = array2hex(id);
      peer_connection = this._socket['get_id_mapping'](string_id);
      if (peer_connection) {
        peer_connection._send_routing_data(data, COMMAND_DATA);
      }
    };
    /**
     * Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity)
     *
     * @param {!Uint8Array}		real_public_key		Ed25519 public key (real one, different from supplied in DHT constructor)
     * @param {!Uint8Array}		real_private_key	Corresponding Ed25519 private key
     * @param {!Uint8Array[]}	introduction_points	Array of public keys of introduction points
     *
     * @return {!Object}
     */
    y$['generate_introduction_message'] = function(real_public_key, real_private_key, introduction_points){
      var time, value, i$, len$, index, introduction_point, signature_data, signature;
      time = +new Date;
      value = new Uint8Array(introduction_points.length * PUBLIC_KEY_LENGTH);
      for (i$ = 0, len$ = introduction_points.length; i$ < len$; ++i$) {
        index = i$;
        introduction_point = introduction_points[i$];
        value.set(introduction_point, index * PUBLIC_KEY_LENGTH);
      }
      signature_data = encode_signature_data({
        'seq': time,
        'v': value
      });
      signature = this._sign(signature_data, real_public_key, real_private_key);
      return {
        'k': real_public_key,
        'seq': time,
        'sig': signature,
        'v': value
      };
    };
    /**
     * Publish message with introduction nodes (typically happens on different node than `generate_introduction_message()`)
     *
     * @param {!Object} message
     */
    y$['publish_introduction_message'] = function(message){
      if (!message['k'] || !message['seq'] || !message['sig'] || !message['v']) {
        return;
      }
      this._dht['put']({
        'k': Buffer.from(message['k']),
        'seq': parseInt(message['seq']),
        'sig': Buffer.from(message['sig']),
        'v': Buffer.from(message['v'])
      });
    };
    /**
     * Find nodes in DHT that are acting as introduction points for specified public key
     *
     * @param {!Uint8Array}					target_public_key
     * @param {!found_introduction_points}	callback
     */
    y$['find_introduction_points'] = function(target_public_key, callback){
      var hash;
      hash = sha3_256(target_public_key);
      this._dht['get'](hash, function(result){
        var introduction_points_bulk, introduction_points, i$, to$, i;
        introduction_points_bulk = Uint8Array.from(result['v']);
        introduction_points = [];
        if (introduction_points_bulk.length % PUBLIC_KEY_LENGTH === 0) {
          return;
        }
        for (i$ = 0, to$ = introduction_points_bulk.length / PUBLIC_KEY_LENGTH; i$ < to$; ++i$) {
          i = i$;
          introduction_points.push(introduction_points_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH));
        }
        callback(introduction_points);
      });
    };
    /**
     * @param {Function} callback
     */
    y$['destroy'] = function(callback){
      this._dht['destroy'](callback);
      delete this._dht;
    };
    Object.defineProperty(DHT.prototype, 'constructor', {
      enumerable: false,
      value: DHT
    });
    /**
     * @constructor
     *
     * @param {number} packet_size			Same as in DHT
     * @param {number} max_pending_segments	How much segments can be in pending state per one address
     *
     * @return {Router}
     */
    function Router(packet_size, max_pending_segments){
      max_pending_segments == null && (max_pending_segments = 10);
      if (!(this instanceof Router)) {
        return new Router(packet_size, max_pending_segments);
      }
      packet_size = packet_size - 2;
      this._ronion = ronion(ROUTING_PROTOCOL_VERSION, packet_size, PUBLIC_KEY_LENGTH, MAC_LENGTH, max_pending_segments);
      asyncEventer.call(this);
    }
    Router.prototype = Object.create(asyncEventer.prototype);
    Object.defineProperty(Router.prototype, 'constructor', {
      enumerable: false,
      value: Router
    });
    return {
      'DHT': DHT,
      'Router': Router
    };
  }
  if (typeof define === 'function' && define['amd']) {
    define(['@detox/dht', 'ronion', 'jssha/src/sha3', 'fixed-size-multiplexer', 'async-eventer'], Transport);
  } else if (typeof exports === 'object') {
    module.exports = Transport(require('@detox/dht'), require('ronion'), require('jssha/src/sha3'), require('fixed-size-multiplexer'), require('async-eventer'));
  } else {
    this['detox_transport'] = Transport(this['detox_dht'], this['ronion'], this['jsSHA'], this['fixed_size_multiplexer'], this['async_eventer']);
  }
}).call(this);
