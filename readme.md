# Detox transport [![Travis CI](https://img.shields.io/travis/Detox/transport/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/transport)
Transport layer implementation for Detox project.

This library provides transport layer implementation with simple API that:
* ensures constant data rate on connection
* supports sending numeric commands with payload
* compresses payloads of DHT commands

## How to install
```
npm install @detox/transport
```

## How to use
Node.js:
```javascript
var detox_transport = require('@detox/transport')

detox_transport.ready(function () {
    // Do stuff
});
```
Browser:
```javascript
requirejs(['@detox/transport'], function (detox_transport) {
    detox_transport.ready(function () {
        // Do stuff
    });
})
```

## API
### detox_transport.P2P_transport(initiator : boolean, ice_servers : Object[], packets_per_second : number) : detox_transport.P2P_transport
Constructor for peer-to-peer transport between 2 nodes in Detox network.

* `initiator` - whether current node initiates connection
* `ice_servers` - array of objects as in [RTCPeerConnection constructor](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection)
* `packets_per_second` - packets are sent at constant rate (which together with fixed packet size of 512 bytes can be used to identify bandwidth requirements for specific connection), `1` is minimal supported rate, actual rate is negotiated between 2 nodes on connection

### detox_transport.P2P_transport.get_signal() : Promise
Resolves with `Uint8Array` signal data that should be sent to remote node.

### detox_transport.P2P_transport.signal(signal : Uint8Array)
* `signal` - as generated by `signal` event

### detox_transport.P2P_transport.send(command : number, data : Uint8Array)
Send command with some payload to the remote node.

* `command` - command from range `[0, 255]`; commands `[0..9]` are considered to be DHT commands and payload sent with these commands are compressed using zlib
* `data` - command payload, for DHT commands (`command <= 9`) up to `detox_transport.MAX_DATA_SIZE - 1` bytes and for other commands up to `detox_transport.MAX_DATA_SIZE` bytes

### detox_transport.P2P_transport.destroy()
Destroy instance, disconnect from the remote node.

### detox_transport.P2P_transport.on(event: string, callback: Function) : detox_transport.P2P_transport
Register event handler.

### detox_transport.P2P_transport.once(event: string, callback: Function) : detox_transport.P2P_transport
Register one-time event handler (just `on()` + `off()` under the hood).

### detox_transport.P2P_transport.off(event: string[, callback: Function]) : detox_transport.P2P_transport
Unregister event handler.

### Event: signal
Payload consists of single `Uint8Array` argument `signal`.

Event is fired when signaling data is available and should be sent to remote node.

### Event: connected
Event is fired when new remote node is connected.

### Event: disconnected
Event is fired when new remote node is disconnected.

### Event: data
Payload consists of two arguments: `command` (`number`) and `data` (`Uint8Array`).
Event is fired when new remote node have sent data using `send()` method.

### detox_transport.MAX_DATA_SIZE : number
Constant that defines max data size supported for sending for non-DHT commands.

### detox_transport.MAX_DHT_DATA_SIZE : number
Constant that defines max data size supported for sending for DHT commands.

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

When reading LiveScript code make sure to configure 1 tab to be 4 spaces (GitHub uses 8 by default), otherwise code might be hard to read.

## License
Free Public License 1.0.0 / Zero Clause BSD License

https://opensource.org/licenses/FPL-1.0.0

https://tldrlegal.com/license/bsd-0-clause-license
