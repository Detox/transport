// Generated by LiveScript 1.5.0
/**
 * @package Detox transport
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
(function(){
  var UNCOMPRESSED_COMMANDS_OFFSET, MAX_DATA_SIZE, MAX_DHT_DATA_SIZE, PACKET_SIZE, PEER_CONNECTION_TIMEOUT;
  UNCOMPRESSED_COMMANDS_OFFSET = 10;
  MAX_DATA_SIZE = Math.pow(2, 16) - 2;
  MAX_DHT_DATA_SIZE = MAX_DATA_SIZE - 1;
  PACKET_SIZE = 512;
  PEER_CONNECTION_TIMEOUT = 30;
  /**
   * @param {!Array<!Uint8Array>}	buffer
   * @param {!Uint8Array}			new_array
   */
  function update_dictionary_buffer(buffer, new_array){
    buffer[0] = buffer[1];
    buffer[1] = buffer[2];
    buffer[2] = buffer[3];
    buffer[3] = buffer[4];
    buffer[4] = new_array;
  }
  /**
   * @param {!Object=} wrtc
   */
  function Wrapper(detoxUtils, fixedSizeMultiplexer, asyncEventer, pako, simplePeer, wrtc){
    var array2string, string2array, concat_arrays, null_array;
    array2string = detoxUtils['array2string'];
    string2array = detoxUtils['string2array'];
    concat_arrays = detoxUtils['concat_arrays'];
    null_array = new Uint8Array(0);
    /**
     * @constructor
     *
     * @param {boolean}			initiator
     * @param {!Array<!Object>}	ice_servers
     * @param {number}			packets_per_second	Each packet send in each direction has exactly the same size and packets are sent at fixed rate (>= 1)
     *
     * @return {!P2P_transport}
     */
    function P2P_transport(initiator, ice_servers, packets_per_second){
      var x$, this$ = this;
      if (!(this instanceof P2P_transport)) {
        return new P2P_transport(initiator, ice_servers, packets_per_second);
      }
      asyncEventer.call(this);
      this._initiator = initiator;
      this._peer = simplePeer({
        'config': {
          'iceServers': ice_servers
        },
        'initiator': initiator,
        'trickle': false,
        'wrtc': wrtc
      });
      this._signal = new Promise(function(resolve, reject){
        var x$;
        x$ = this$._peer;
        x$['once']('signal', function(signal){
          resolve(string2array(signal['sdp']));
        });
        x$['once']('close', reject);
      });
      this._signal['catch'](function(){});
      this._send_delay = 1000 / packets_per_second;
      this._sending = initiator;
      this._multiplexer = fixedSizeMultiplexer['Multiplexer'](MAX_DATA_SIZE, PACKET_SIZE);
      this._demultiplexer = fixedSizeMultiplexer['Demultiplexer'](MAX_DATA_SIZE, PACKET_SIZE);
      this._send_zlib_buffer = [null_array, null_array, null_array, null_array, null_array];
      this._receive_zlib_buffer = [null_array, null_array, null_array, null_array, null_array];
      x$ = this._peer;
      x$['once']('connect', function(){
        this$['fire']('connected');
        this$._last_sent = +new Date;
        if (this$._sending) {
          this$._real_send();
        }
      });
      x$['once']('close', function(){
        this$['fire']('disconnected');
      });
      x$['on']('data', function(data){
        var demultiplexed_data, command, command_data;
        if (this$._sending || data.length !== PACKET_SIZE) {
          this$['destroy']();
        } else {
          this$._demultiplexer['feed'](data);
          while (this$._demultiplexer['have_more_data']()) {
            demultiplexed_data = this$._demultiplexer['get_data']();
            command = demultiplexed_data[0];
            command_data = demultiplexed_data.subarray(1);
            if (command < UNCOMPRESSED_COMMANDS_OFFSET) {
              command_data = this$._zlib_decompress(command_data);
            }
            this$['fire']('data', command, command_data);
          }
          this$._sending = true;
          this$._real_send();
        }
      });
    }
    P2P_transport.prototype = {
      /**
       * @return {!Promise} Resolves with `Uint8Array` signaling data
       */
      'get_signaling': function(){
        return this._signal;
      }
      /**
       * @param {!Uint8Array} signaling As generated by `get_signaling()` method
       */,
      'set_signaling': function(signaling){
        this._peer['signal']({
          'type': this._initiator ? 'answer' : 'offer',
          'sdp': array2string(signaling)
        });
      }
      /**
       * @param {number}		command
       * @param {!Uint8Array}	data
       */,
      'send': function(command, data){
        var data_with_header;
        if (data.length > MAX_DATA_SIZE) {
          return;
        }
        if (command < UNCOMPRESSED_COMMANDS_OFFSET) {
          if (data.length > MAX_DHT_DATA_SIZE) {
            return;
          }
          data = this._zlib_compress(data);
        }
        data_with_header = concat_arrays([[command], data]);
        this._multiplexer['feed'](data_with_header);
      },
      'destroy': function(){
        this._destroyed = true;
        clearTimeout(this._timeout);
        this._peer['destroy']();
      }
      /**
       * Send a block of multiplexed data to the other side
       */,
      _real_send: function(){
        var delay, this$ = this;
        delay = Math.max(0, this._send_delay - (new Date - this._last_sent));
        this._timeout = setTimeout(function(){
          if (this$._destroyed) {
            return;
          }
          try {
            this$._peer['send'](this$._multiplexer['get_block']());
            this$._sending = false;
            this$._last_sent = +new Date;
          } catch (e$) {}
        }, delay);
      }
      /**
       * @param {!Uint8Array} data
       *
       * @return {!Uint8Array}
       */,
      _zlib_compress: function(data){
        var result;
        result = pako['deflate'](data, {
          'dictionary': concat_arrays(this._send_zlib_buffer),
          'level': 1
        });
        update_dictionary_buffer(this._send_zlib_buffer, data);
        if (result.length > MAX_DHT_DATA_SIZE) {
          return concat_arrays([[0], data]);
        } else {
          return concat_arrays([[1], result]);
        }
      }
      /**
       * @param {!Uint8Array} data
       *
       * @return {!Uint8Array}
       */,
      _zlib_decompress: function(data){
        var compressed, result;
        compressed = data[0];
        data = data.subarray(1);
        if (compressed) {
          result = pako['inflate'](data, {
            'dictionary': concat_arrays(this._receive_zlib_buffer)
          });
        } else {
          result = data;
        }
        update_dictionary_buffer(this._receive_zlib_buffer, result);
        return result;
      }
    };
    P2P_transport.prototype = Object.assign(Object.create(asyncEventer.prototype), P2P_transport.prototype);
    Object.defineProperty(P2P_transport.prototype, 'constructor', {
      value: P2P_transport
    });
    return {
      'P2P_transport': P2P_transport,
      'MAX_DATA_SIZE': MAX_DATA_SIZE,
      'MAX_DHT_DATA_SIZE': MAX_DHT_DATA_SIZE
    };
  }
  if (typeof define === 'function' && define['amd']) {
    define(['@detox/utils', 'fixed-size-multiplexer', 'async-eventer', 'pako', '@detox/simple-peer'], Wrapper);
  } else if (typeof exports === 'object') {
    module.exports = Wrapper(require('@detox/utils'), require('fixed-size-multiplexer'), require('async-eventer'), require('pako'), require('@detox/simple-peer'), require('wrtc'));
  } else {
    this['detox_transport'] = Wrapper(this['detox_utils'], this['fixed_size_multiplexer'], this['async_eventer'], this['pako'], this['SimplePeer']);
  }
}).call(this);
