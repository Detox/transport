// Generated by LiveScript 1.5.0
/**
 * @package   Detox transport
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
(function(){
  var COMMAND_DHT, COMMAND_DATA, COMMAND_TAG, COMMAND_UNTAG, ROUTING_PROTOCOL_VERSION, PUBLIC_KEY_LENGTH, MAC_LENGTH, MIN_PACKET_SIZE, ROUTING_PATH_SEGMENT_TIMEOUT, MAX_DATA_SIZE, PEER_CONNECTION_TIMEOUT;
  COMMAND_DHT = 0;
  COMMAND_DATA = 1;
  COMMAND_TAG = 2;
  COMMAND_UNTAG = 3;
  ROUTING_PROTOCOL_VERSION = 0;
  PUBLIC_KEY_LENGTH = 32;
  MAC_LENGTH = 16;
  MIN_PACKET_SIZE = 256;
  ROUTING_PATH_SEGMENT_TIMEOUT = 10;
  MAX_DATA_SIZE = Math.pow(2, 16) - 1;
  PEER_CONNECTION_TIMEOUT = 30;
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
      string += byte.toString(16).padStart(2, '0');
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
   * @param {string}		string
   * @param {!Uint8Array}	array
   *
   * @return {boolean}
   */
  function is_string_equal_to_array(string, array){
    return string === array.join(',');
  }
  /**
   * @param {!Uint8Array}	address
   * @param {!Uint8Array}	segment_id
   *
   * @return {string}
   */
  function compute_source_id(address, segment_id){
    return address.join(',') + segment_id.join(',');
  }
  function Transport(detoxCrypto, detoxDht, ronion, jsSHA, fixedSizeMultiplexer, asyncEventer){
    var bencode, simplePeer, webrtcSocket, webtorrentDht, Buffer, x$, y$, z$;
    bencode = detoxDht['bencode'];
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
      this._sign = options['sign'];
      this._packet_size = options['packet_size'];
      this._packets_per_second = options['packets_per_second'];
      this._sending = options['initiator'];
      this['once']('connect', function(){
        this$._send_delay = 1000 / this$._packets_per_second;
        this$._multiplexer = fixedSizeMultiplexer['Multiplexer'](MAX_DATA_SIZE, this$._packet_size);
        this$._demultiplexer = fixedSizeMultiplexer['Demultiplexer'](MAX_DATA_SIZE, this$._packet_size);
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
        data['signature'] = Buffer.from(this._sign(string2array(data['sdp'])));
        simplePeer.prototype['emit'].call(this, 'signal', data);
        break;
      case 'data':
        if (this._sending) {
          this['destroy']();
          return;
        } else if (data.length !== this._packet_size) {
          this['destroy']();
          return;
        } else {
          this._demultiplexer['feed'](data);
          while (this._demultiplexer['have_more_data']()) {
            actual_data = this._demultiplexer['get_data']();
            command = actual_data[0];
            if (command === COMMAND_DHT) {
              simplePeer.prototype['emit'].call(this, 'data', Buffer.from(actual_data.subarray(1)));
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
      if (!signal['signature'] || !signal['extensions']) {
        this['destroy']();
        return;
      }
      this._signature_received = signal['signature'];
      this._sdp_received = string2array(signal['sdp']);
      found_psr = false;
      for (i$ = 0, len$ = (ref$ = signal['extensions']).length; i$ < len$; ++i$) {
        extension = ref$[i$];
        if (extension.startsWith('psr:')) {
          array = extension.split(':');
          received_packet_size = parseInt(array[1], 10);
          received_packets_per_second = parseInt(array[2], 10);
          if (received_packet_size < MIN_PACKET_SIZE || received_packets_per_second < 1) {
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
      simplePeer.prototype['signal'].call(this, signal);
    };
    /**
     * Data sending method that will be used by DHT
     *
     * @param {!Uint8Array} data
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
        if (this$['destroyed']) {
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
      shaObj['update'](data);
      return Buffer.from(shaObj['getHash']('ARRAYBUFFER'));
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
     * @param {!Uint8Array}		dht_public_key		Ed25519 public key, temporary one, just for DHT operation
     * @param {!Uint8Array}		dht_private_key		Corresponding Ed25519 private key
     * @param {!Array<!Object>}	bootstrap_nodes
     * @param {!Array<!Object>}	ice_servers
     * @param {number}			packet_size
     * @param {number}			packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
     * @param {number}			bucket_size
     *
     * @return {!DHT}
     *
     * @throws {Error}
     */
    function DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size){
      var extensions, x$, y$, this$ = this;
      bucket_size == null && (bucket_size = 2);
      if (!(this instanceof DHT)) {
        return new DHT(dht_public_key, dht_private_key, bootstrap_nodes, ice_servers, packet_size, packets_per_second, bucket_size);
      }
      if (packet_size < MIN_PACKET_SIZE) {
        throw new Error('Minimal supported packet size is ' + MIN_PACKET_SIZE);
      }
      asyncEventer.call(this);
      if (packets_per_second < 1) {
        packets_per_second = 1;
      }
      this._pending_websocket_ids = new Map;
      extensions = ["psr:" + packet_size + ":" + packets_per_second];
      x$ = this._socket = webrtcSocket({
        'extensions': extensions,
        'simple_peer_constructor': simplePeerDetox,
        'simple_peer_opts': {
          'config': {
            'iceServers': ice_servers
          },
          'packet_size': packet_size,
          'packets_per_second': packets_per_second,
          'sign': function(data){
            return detoxCrypto['sign'](data, dht_public_key, dht_private_key);
          }
        }
      });
      x$['on']('websocket_peer_connection_alias', function(websocket_host, websocket_port, peer_connection){
        bootstrap_nodes.forEach(function(bootstrap_node){
          if (bootstrap_node.host !== websocket_host || bootstrap_node.port !== websocket_port) {
            return;
          }
          this$._pending_websocket_ids.set(peer_connection, bootstrap_node['node_id']);
          return peer_connection['on']('close', function(){
            this$._pending_websocket_ids['delete'](peer_connection);
          });
        });
      });
      x$['on']('node_connected', function(string_id){
        var id, peer_connection, expected_id;
        id = hex2array(string_id);
        peer_connection = this$._socket['get_id_mapping'](string_id);
        if (this$._pending_websocket_ids.has(peer_connection)) {
          expected_id = this$._pending_websocket_ids.get(peer_connection);
          this$._pending_websocket_ids['delete'](peer_connection);
          if (expected_id !== string_id) {
            peer_connection['destroy']();
            return;
          }
        }
        if (!detoxCrypto['verify'](peer_connection._signature_received, peer_connection._sdp_received, id)) {
          peer_connection['destroy']();
          return;
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
      y$ = this._dht = new webtorrentDht({
        'bootstrap': bootstrap_nodes,
        'extensions': extensions,
        'hash': sha3_256,
        'k': bucket_size,
        'nodeId': Buffer.from(dht_public_key),
        'socket': this._socket,
        'timeout': PEER_CONNECTION_TIMEOUT * 1000,
        'verify': detoxCrypto['verify']
      });
      y$['on']('error', function(error){
        this$['fire']('error', error);
      });
      y$['once']('ready', function(){
        this$['fire']('ready');
      });
    }
    DHT.prototype = Object.create(asyncEventer.prototype);
    y$ = DHT.prototype;
    /**
     * Start WebSocket server listening on specified ip:port, so that current node will be capable of acting as bootstrap node for other users
     *
     * @param {string}	ip
     * @param {number}	port
     */
    y$['start_bootstrap_node'] = function(ip, port){
      this._dht['listen'](port, ip);
    };
    /**
     * Get an array of bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor
     *
     * @return {!Array<!Object>} Each element is an object with keys `host`, `port` and `node_id`
     */
    y$['get_bootstrap_nodes'] = function(){
      var peer_connection;
      return (function(){
        var i$, ref$, results$ = [];
        for (i$ in ref$ = this._dht['_rpc']['socket']['socket']['_peer_connections']) {
          peer_connection = ref$[i$];
          if (peer_connection['ws_server'] && peer_connection['id']) {
            results$.push({
              'node_id': peer_connection['id'],
              'host': peer_connection['ws_server']['host'],
              'port': peer_connection['ws_server']['port']
            });
          }
        }
        return results$;
      }.call(this)).filter(Boolean);
    };
    /**
     * Start lookup for specified node ID (listen for `node_connected` in order to know when interested node was connected)
     *
     * @param {!Uint8Array} id
     */
    y$['lookup'] = function(id){
      this._dht['lookup'](Buffer.from(id));
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
     * @param {!Uint8Array}			real_public_key		Ed25519 public key (real one, different from supplied in DHT constructor)
     * @param {!Uint8Array}			real_private_key	Corresponding Ed25519 private key
     * @param {!Array<!Uint8Array>}	introduction_nodes	Array of public keys of introduction points
     *
     * @return {!Object}
     */
    y$['generate_introduction_message'] = function(real_public_key, real_private_key, introduction_nodes){
      var time, value, i$, len$, index, introduction_point, signature_data, signature;
      time = +new Date;
      value = new Uint8Array(introduction_nodes.length * PUBLIC_KEY_LENGTH);
      for (i$ = 0, len$ = introduction_nodes.length; i$ < len$; ++i$) {
        index = i$;
        introduction_point = introduction_nodes[i$];
        value.set(introduction_point, index * PUBLIC_KEY_LENGTH);
      }
      signature_data = encode_signature_data({
        'seq': time,
        'v': Buffer.from(value)
      });
      signature = detoxCrypto['sign'](signature_data, real_public_key, real_private_key);
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
        'seq': parseInt(message['seq'], 10),
        'sig': Buffer.from(message['sig']),
        'v': Buffer.from(message['v'])
      });
    };
    /**
     * Find nodes in DHT that are acting as introduction points for specified public key
     *
     * @param {!Uint8Array}	target_public_key
     * @param {!Function}	success_callback
     * @param {!Function}	failure_callback
     */
    y$['find_introduction_nodes'] = function(target_public_key, success_callback, failure_callback){
      var hash;
      hash = sha3_256(target_public_key);
      this._dht['get'](hash, function(arg$, result){
        var introduction_nodes_bulk, introduction_nodes, i$, to$, i;
        if (!result || !result['v']) {
          failure_callback();
          return;
        }
        introduction_nodes_bulk = Uint8Array.from(result['v']);
        introduction_nodes = [];
        if (introduction_nodes_bulk.length % PUBLIC_KEY_LENGTH !== 0) {
          return;
        }
        for (i$ = 0, to$ = introduction_nodes_bulk.length / PUBLIC_KEY_LENGTH; i$ < to$; ++i$) {
          i = i$;
          introduction_nodes.push(introduction_nodes_bulk.subarray(i * PUBLIC_KEY_LENGTH, (i + 1) * PUBLIC_KEY_LENGTH));
        }
        success_callback(introduction_nodes);
      });
    };
    /**
     * Stop WebSocket server if running, close all active WebRTC connections
     *
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
     * @param {!Uint8Array}	dht_private_key			X25519 private key that corresponds to Ed25519 key used in `DHT` constructor
     * @param {number}		packet_size				The same as in `DHT` constructor
     * @param {number}		max_pending_segments	How much segments can be in pending state per one address
     *
     * @return {!Router}
     *
     * @throws {Error}
     */
    function Router(dht_private_key, packet_size, max_pending_segments){
      var this$ = this;
      max_pending_segments == null && (max_pending_segments = 10);
      if (!(this instanceof Router)) {
        return new Router(dht_private_key, packet_size, max_pending_segments);
      }
      if (packet_size < MIN_PACKET_SIZE) {
        throw new Error('Minimal supported packet size is ' + MIN_PACKET_SIZE);
      }
      asyncEventer.call(this);
      packet_size = packet_size - 3;
      this._encryptor_instances = new Map;
      this._rewrapper_instances = new Map;
      this._last_node_in_routing_path = new Map;
      this._multiplexer = new Map;
      this._demultiplexer = new Map;
      this._established_routing_paths = new Map;
      this._ronion = ronion(ROUTING_PROTOCOL_VERSION, packet_size, PUBLIC_KEY_LENGTH, MAC_LENGTH, max_pending_segments)['on']('create_request', function(data){
        var address, segment_id, command_data, source_id, encryptor_instance, e, rewrapper_instance, address_string, encryptor_instances, rewrapper_instances;
        address = data['address'];
        segment_id = data['segment_id'];
        command_data = data['command_data'];
        source_id = compute_source_id(address, segment_id);
        if (this$._encryptor_instances.has(source_id)) {
          return;
        }
        encryptor_instance = detoxCrypto['Encryptor'](false, dht_private_key);
        try {
          encryptor_instance['put_handshake_message'](command_data);
        } catch (e$) {
          e = e$;
          return;
        }
        this$._ronion['create_response'](address, segment_id, encryptor_instance['get_handshake_message']());
        this$._ronion['confirm_incoming_segment_established'](address, segment_id);
        this$._multiplexer.set(source_id, fixedSizeMultiplexer['Multiplexer'](MAX_DATA_SIZE, this$._max_packet_data_size));
        this$._demultiplexer.set(source_id, fixedSizeMultiplexer['Demultiplexer'](MAX_DATA_SIZE, this$._max_packet_data_size));
        if (!encryptor_instance['ready']()) {
          return;
        }
        rewrapper_instance = encryptor_instance['get_rewrapper_keys']().map(detoxCrypto['Rewrapper']);
        address_string = address.join(',');
        encryptor_instances = Object.create(null);
        encryptor_instances[address_string] = encryptor_instance;
        rewrapper_instances = Object.create(null);
        rewrapper_instances[address_string] = rewrapper_instance;
        this$._encryptor_instances.set(source_id, encryptor_instances);
        this$._rewrapper_instances.set(source_id, rewrapper_instances);
        this$._last_node_in_routing_path.set(source_id, address);
      })['on']('send', function(data){
        this$['fire']('send', data['address'], data['packet']);
      })['on']('data', function(data){
        var address, segment_id, target_address, command_data, source_id, last_node_in_routing_path, demultiplexer;
        address = data['address'];
        segment_id = data['segment_id'];
        target_address = data['target_address'];
        command_data = data['command_data'];
        source_id = compute_source_id(address, segment_id);
        last_node_in_routing_path = this$._last_node_in_routing_path.get(source_id);
        if (target_address.join(',') !== last_node_in_routing_path.join(',')) {
          return;
        }
        demultiplexer = this$._demultiplexer.get(source_id);
        if (!demultiplexer) {
          return;
        }
        demultiplexer['feed'](command_data);
        if (demultiplexer['have_more_data']()) {
          data = demultiplexer['get_data']();
          this$['fire']('data', address, segment_id, data);
        }
      })['on']('destroy', function(data){
        var address, segment_id;
        address = data['address'];
        segment_id = data['segment_id'];
        this$._destroy_routing_path(address, segment_id);
        this$['fire']('destroyed', address, segment_id);
      })['on']('encrypt', function(data){
        var address, segment_id, target_address, plaintext, source_id, target_address_string, encryptor_instance, ref$;
        address = data['address'];
        segment_id = data['segment_id'];
        target_address = data['target_address'];
        plaintext = data['plaintext'];
        source_id = compute_source_id(address, segment_id);
        target_address_string = target_address.join(',');
        encryptor_instance = (ref$ = this$._encryptor_instances.get(source_id)) != null ? ref$[target_address_string] : void 8;
        if (!encryptor_instance) {
          return;
        }
        data['ciphertext'] = encryptor_instance['encrypt'](plaintext);
      })['on']('decrypt', function(data){
        var address, segment_id, target_address, ciphertext, source_id, target_address_string, encryptor_instance, ref$;
        address = data['address'];
        segment_id = data['segment_id'];
        target_address = data['target_address'];
        ciphertext = data['ciphertext'];
        source_id = compute_source_id(address, segment_id);
        target_address_string = target_address.join(',');
        encryptor_instance = (ref$ = this$._encryptor_instances.get(source_id)) != null ? ref$[target_address_string] : void 8;
        if (!encryptor_instance) {
          return;
        }
        try {
          data['plaintext'] = encryptor_instance['decrypt'](ciphertext);
        } catch (e$) {}
      })['on']('wrap', function(data){
        var address, segment_id, target_address, unwrapped, source_id, target_address_string, rewrapper_instance, ref$, ref1$;
        address = data['address'];
        segment_id = data['segment_id'];
        target_address = data['target_address'];
        unwrapped = data['unwrapped'];
        source_id = compute_source_id(address, segment_id);
        target_address_string = target_address.join(',');
        rewrapper_instance = (ref$ = this$._rewrapper_instances.get(source_id)) != null ? (ref1$ = ref$[target_address_string]) != null ? ref1$[0] : void 8 : void 8;
        if (!rewrapper_instance) {
          return;
        }
        data['wrapped'] = rewrapper_instance['wrap'](unwrapped);
      })['on']('unwrap', function(data){
        var address, segment_id, target_address, wrapped, source_id, target_address_string, rewrapper_instance, ref$, ref1$;
        address = data['address'];
        segment_id = data['segment_id'];
        target_address = data['target_address'];
        wrapped = data['wrapped'];
        source_id = compute_source_id(address, segment_id);
        target_address_string = target_address.join(',');
        rewrapper_instance = (ref$ = this$._rewrapper_instances.get(source_id)) != null ? (ref1$ = ref$[target_address_string]) != null ? ref1$[1] : void 8 : void 8;
        if (!rewrapper_instance) {
          return;
        }
        data['unwrapped'] = rewrapper_instance['unwrap'](wrapped);
      });
      this._max_packet_data_size = this._ronion['get_max_command_data_length']();
    }
    Router.prototype = Object.create(asyncEventer.prototype);
    z$ = Router.prototype;
    /**
     * Process routing packet coming from node with specified ID
     *
     * @param {!Uint8Array} node_id
     * @param {!Uint8Array} packet
     */
    z$['process_packet'] = function(node_id, packet){
      this._ronion['process_packet'](node_id, packet);
    };
    /**
     * Construct routing path through specified nodes
     *
     * @param {!Array<!Uint8Array>} nodes IDs of the nodes through which routing path must be constructed, last node in the list is responder
     *
     * @return {!Promise} Will resolve with ID of the route or will be rejected if path construction fails
     */
    z$['construct_routing_path'] = function(nodes){
      var this$ = this;
      nodes = nodes.slice();
      return new Promise(function(resolve){
        var last_node_in_routing_path, first_node, first_node_string, encryptor_instances, rewrapper_instances, fail, x25519_public_key, segment_establishment_timeout, route_id, route_id_string, source_id;
        last_node_in_routing_path = nodes[nodes.length - 1];
        first_node = nodes.shift();
        first_node_string = first_node.join(',');
        encryptor_instances = Object.create(null);
        rewrapper_instances = Object.create(null);
        fail = function(){
          this$._destroy_routing_path(first_node, route_id);
          throw new Error('Routing path creation failed');
        };
        x25519_public_key = detoxCrypto['convert_public_key'](first_node);
        if (!x25519_public_key) {
          fail();
        }
        encryptor_instances[first_node_string] = detoxCrypto['Encryptor'](true, x25519_public_key);
        function create_response_handler(data){
          var address, segment_id, command_data, e, current_node, current_node_string, segment_extension_timeout;
          address = data['address'];
          segment_id = data['segment_id'];
          command_data = data['command_data'];
          if (!is_string_equal_to_array(first_node_string, address) || !is_string_equal_to_array(route_id_string, segment_id)) {
            return;
          }
          clearTimeout(segment_establishment_timeout);
          this$._ronion['off']('create_response', create_response_handler);
          try {
            encryptor_instances[first_node_string]['put_handshake_message'](command_data);
          } catch (e$) {
            e = e$;
            fail();
          }
          if (!encryptor_instances[first_node_string]['ready']()) {
            fail();
          }
          rewrapper_instances[first_node_string] = encryptor_instances[first_node_string]['get_rewrapper_keys']().map(detoxCrypto['Rewrapper']);
          this$._ronion['confirm_outgoing_segment_established'](first_node, route_id);
          this$._multiplexer.set(source_id, fixedSizeMultiplexer['Multiplexer'](MAX_DATA_SIZE, this$._max_packet_data_size));
          this$._demultiplexer.set(source_id, fixedSizeMultiplexer['Demultiplexer'](MAX_DATA_SIZE, this$._max_packet_data_size));
          function extend_request(){
            var x25519_public_key;
            if (!nodes.length) {
              this$._established_routing_paths.set(source_id, [first_node, route_id]);
              resolve(route_id);
              return;
            }
            function extend_response_handler(data){
              var address, segment_id, command_data, e;
              address = data['address'];
              segment_id = data['segment_id'];
              command_data = data['command_data'];
              if (!is_string_equal_to_array(first_node_string, address) || !is_string_equal_to_array(route_id_string, segment_id)) {
                return;
              }
              this$._ronion['off']('extend_response', extend_response_handler);
              clearTimeout(segment_extension_timeout);
              if (!command_data.length) {
                fail();
              }
              try {
                encryptor_instances[current_node_string]['put_handshake_message'](command_data);
              } catch (e$) {
                e = e$;
                fail();
              }
              if (!encryptor_instances[current_node_string]['ready']()) {
                fail();
              }
              rewrapper_instances[current_node_string] = encryptor_instances[current_node_string]['get_rewrapper_keys']().map(detoxCrypto['Rewrapper']);
              this$._ronion['confirm_extended_path'](first_node, route_id);
              extend_request();
            }
            this$._ronion['on']('extend_response', extend_response_handler);
            current_node = nodes.shift();
            current_node_string = current_node.join(',');
            x25519_public_key = detoxCrypto['convert_public_key'](current_node);
            if (!x25519_public_key) {
              fail();
            }
            encryptor_instances[current_node_string] = detoxCrypto['Encryptor'](true, x25519_public_key);
            segment_extension_timeout = setTimeout(function(){
              this$._ronion['off']('extend_response', extend_response_handler);
              fail();
            }, ROUTING_PATH_SEGMENT_TIMEOUT * 1000);
            this$._ronion['extend_request'](first_node, route_id, current_node, encryptor_instances[current_node_string]['get_handshake_message']());
          }
          extend_request();
        }
        this$._ronion['on']('create_response', create_response_handler);
        segment_establishment_timeout = setTimeout(function(){
          this$._ronion['off']('create_response', create_response_handler);
          fail();
        }, ROUTING_PATH_SEGMENT_TIMEOUT * 1000);
        route_id = this$._ronion['create_request'](first_node, encryptor_instances[first_node_string]['get_handshake_message']());
        route_id_string = route_id.join(',');
        source_id = compute_source_id(first_node, route_id);
        this$._encryptor_instances.set(source_id, encryptor_instances);
        this$._rewrapper_instances.set(source_id, rewrapper_instances);
        this$._last_node_in_routing_path.set(source_id, last_node_in_routing_path);
      });
    };
    /**
     * Destroy routing path constructed earlier
     *
     * @param {!Uint8Array} node_id		First node in routing path
     * @param {!Uint8Array} route_id	Identifier returned during routing path construction
     */
    z$['destroy_routing_path'] = function(node_id, route_id){
      this._destroy_routing_path(node_id, route_id);
    };
    /**
     * Send data to the responder on specified routing path
     *
     * @param {!Uint8Array} node_id		First node in routing path
     * @param {!Uint8Array} route_id	Identifier returned during routing path construction
     * @param {!Uint8Array} data
     */
    z$['send_data'] = function(node_id, route_id, data){
      var source_id, target_address, multiplexer, data_block;
      if (data.length > MAX_DATA_SIZE) {
        return;
      }
      source_id = compute_source_id(node_id, route_id);
      target_address = this._last_node_in_routing_path.get(source_id);
      multiplexer = this._multiplexer.get(source_id);
      if (!multiplexer) {
        return;
      }
      multiplexer['feed'](data);
      while (multiplexer['have_more_blocks']()) {
        data_block = multiplexer['get_block']();
        this._ronion['data'](node_id, route_id, target_address, data_block);
      }
    };
    /**
     * Destroy all of the routing path constructed earlier
     */
    z$['destroy'] = function(){
      var this$ = this;
      this._established_routing_paths.forEach(function(arg$){
        var address, segment_id;
        address = arg$[0], segment_id = arg$[1];
        this$._destroy_routing_path(address, segment_id);
      });
    };
    /**
     * @param {!Uint8Array} address
     * @param {!Uint8Array} segment_id
     */
    z$._destroy_routing_path = function(address, segment_id){
      var source_id, encryptor_instances, counter, this$ = this;
      source_id = compute_source_id(address, segment_id);
      encryptor_instances = this._encryptor_instances.get(source_id);
      if (!encryptor_instances) {
        return;
      }
      counter = Object.keys(encryptor_instances).length;
      function destroy_segment(){
        var e, i$, ref$, encryptor_instance;
        if (counter) {
          --counter;
          try {
            this$._ronion['destroy'](address, segment_id);
            this$._ronion['once']('send', function(){
              destroy_segment();
            });
          } catch (e$) {
            e = e$;
            destroy_segment();
          }
        } else {
          for (i$ in ref$ = encryptor_instances) {
            encryptor_instance = ref$[i$];
            encryptor_instance['destroy']();
          }
          this$._encryptor_instances['delete'](source_id);
          this$._rewrapper_instances['delete'](source_id);
          this$._last_node_in_routing_path['delete'](source_id);
          this$._multiplexer['delete'](source_id);
          this$._demultiplexer['delete'](source_id);
          this$._established_routing_paths['delete'](source_id);
        }
      }
      destroy_segment();
    };
    Object.defineProperty(Router.prototype, 'constructor', {
      enumerable: false,
      value: Router
    });
    return {
      'ready': detoxCrypto['ready'],
      'DHT': DHT,
      'Router': Router
    };
  }
  if (typeof define === 'function' && define['amd']) {
    define(['@detox/crypto', '@detox/dht', 'ronion', 'jssha/src/sha3', 'fixed-size-multiplexer', 'async-eventer'], Transport);
  } else if (typeof exports === 'object') {
    module.exports = Transport(require('@detox/crypto'), require('@detox/dht'), require('ronion'), require('jssha/src/sha3'), require('fixed-size-multiplexer'), require('async-eventer'));
  } else {
    this['detox_transport'] = Transport(this['detox_crypto'], this['detox_dht'], this['ronion'], this['jsSHA'], this['fixed_size_multiplexer'], this['async_eventer']);
  }
}).call(this);
