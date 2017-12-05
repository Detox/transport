# Detox transport [![Travis CI](https://img.shields.io/travis/Detox/detox-transport/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/detox-transport)
High-level utilities that combine under simple interfaces complexity of the transport layer used in Detox project.

Essentially provides wrapper functions and objects for:
* DHT (based on [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht))
* Anonymous routing (based on [Ronion](https://github.com/nazar-pc/ronion))
* Both of above use `@detox-crypto` for cryptographic needs

# API
### detox_transport.ready(callback)
* `callback` - Callback function that is called when library is ready for use

### detox_transport.DHT(dht_public_key : Uint8Array, dht_private_key : Uint8Array, bootstrap_nodes : Object[], ice_servers : Object[], packet_size : number, packets_per_second : number, bucket_size = 2 : number) : detox_transport.DHT
Constructor for DHT object, offers BitTorrent-like DHT based on [WebTorrent DHT](https://github.com/nazar-pc/webtorrent-dht) with just a few high-level APIs available for the user.

* `dht_public_key` and `dht_private_key` - are Ed25519 keypair as in `@detox/crypto` used to represent node itself in DHT network, typically temporary
* `bootstrap_nodes` - array of objects with keys (all of them are required) `node_id` (`dht_public_key` of corresponding node), `host` and `ip`
* `ice_servers` - array of objects as `config.iceServers` in [simple-peer constructor](https://github.com/feross/simple-peer#peer--new-simplepeeropts)
* `packet_size` - data are always sent over the network in packets of this fixed size, `256` is minimal supported size, actual size is negotiated between 2 sides on connection
* `packets_per_second` - packets are sent at constant rate (which together with `packet_size` can be used to identify bandwidth requirements for specific connection), `1` is minimal supported rate, actual rate is negotiated between 2 sides on connection
* `bucket_size` - size of the bucket used in DHT internals (directly affects number of active WebRTC connections)

### detox_transport.DHT.start_bootstrap_node(ip : string, port : number)
Start bootstrap server (WebSocket) listening on specified IP and port.

### detox_transport.DHT.get_bootstrap_nodes() : Object
Returns array of collected bootstrap nodes obtained during DHT operation in the same format as `bootstrap_nodes` argument in constructor.

### detox_transport.DHT.lookup(id : Uint8Array)
Start lookup for specified node ID (listen for `node_connected` in order to know when interested node was connected).

### detox_transport.DHT.add_used_tag(id : Uint8Array)
Tag connection to specified node ID as used, so that it is not disconnected when not used by DHT itself.

### detox_transport.DHT.del_used_tag(id : Uint8Array)
Remove tag from connection, so that it can be disconnected if not needed by DHT anymore.

### detox_transport.DHT.send_data(id : Uint8Array, data : Uint8Array)
Send data to specified node ID.

### detox_transport.DHT.generate_introduction_message(real_public_key : Uint8Array, real_private_key : Uint8Array, introduction_nodes : Uint8Array[]) : Object
Generate message with introduction nodes that can later be published by any node connected to DHT (typically other node than this for anonymity).

Introduction message that contains a list of introduction nodes that can be used to contact user of real long-term keypair.

`dht_public_key` and `dht_private_key` are Ed25519 keypair as in `@detox/crypto` that is typically different from DHT keypair and is used as real long-term keypair.
`introduction_nodes` is a list of nodes IDs (`dht_public_key` of corresponding nodes).

### detox_transport.DHT.publish_introduction_message(message : Object)
Publish message with introduction nodes (typically happens on different node than `generate_introduction_message()`)

### detox_transport.DHT.find_introduction_nodes(target_public_key : Uint8Array, callback : Function)
Find nodes in DHT that are acting as introduction points for specified public key.

### detox_transport.DHT.destroy(callback : Function)
Stop WebSocket server if running, close all active WebRTC connections.

### detox_transport.DHT.on(event: string, callback: Function) : detox_transport.DHT
Register event handler.

### detox_transport.DHT.once(event: string, callback: Function) : detox_transport.DHT
Register one-time event handler (just `on()` + `off()` under the hood).

### detox_transport.DHT.off(event: string[, callback: Function]) : detox_transport.DHT
Unregister event handler.

### Event: node_connected
Payload is single `Uint8Array` argument `id`.
Event is fired when new remote node is connected to our DHT instance.

### Event: node_disconnected
Payload is single `Uint8Array` argument `id`.
Event is fired when new remote node is disconnected to our DHT instance.

### Event: node_tagged
Payload is single `Uint8Array` argument `id`.
Event is fired when new remote node tagged connection as used using `add_used_tag()` method.

### Event: node_untagged
Payload is single `Uint8Array` argument `id`.
Event is fired when new remote node untagged connection as used using `del_used_tag()` method.

### Event: data
Payload consists of two `Uint8Array` arguments: `id` and `data`.
Event is fired when new remote node have sent data using `send_data()` method.

### Event: ready
No payload.
Event is fired when DHT instance is ready to be used.

### Event: error
Payload is single argument `error`.
Event is fired when errors occur in underlying DHT implementation.

### detox_transport.Router(dht_private_key : Uint8Array, packet_size, max_pending_segments = 10) : detox_transport.Router
Constructor for Router object, offers anonymous routing functionality based on [Ronion](https://github.com/nazar-pc/ronion) spec and reference implementation with just a few high-level APIs available for the user.

* `dht_private_key` - X25519 private key that corresponds to Ed25519 key used in `DHT` constructor
* `packet_size` - the same as in `DHT` constructor
* `max_pending_segments` - How much segments can be in pending state per one address

### detox_transport.Router.process_packet(node_id : Uint8Array, packet : Uint8Array)
Process routing packet coming from node with specified ID.

### detox_transport.Router.construct_routing_path(nodes : Uint8Array[]) : Promise
Construct routing path through specified nodes.

* `nodes` - IDs of the nodes through which routing path must be constructed, last node in the list is responder

Returned promise will resolve with ID of the route or will be rejected if path construction fails.

### detox_transport.Router.destroy_routing_path(node_id : Uint8Array, route_id : Uint8Array)
Destroy routing path constructed earlier.

* `node_id` - first node in routing path
* `route_id` - identifier returned during routing path construction

### detox_transport.Router.send_data(node_id : Uint8Array, route_id : Uint8Array, data : Uint8Array)
Send data to the responder on specified routing path.

* `node_id` - first node in routing path
* `route_id` - identifier returned during routing path construction
* `data` - data being sent

### detox_transport.Router.destroy()
Destroy all of the routing path constructed earlier.

### detox_transport.Router.on(event: string, callback: Function) : detox_transport.Router
Register event handler.

### detox_transport.Router.once(event: string, callback: Function) : detox_transport.Router
Register one-time event handler (just `on()` + `off()` under the hood).

### detox_transport.Router.off(event: string[, callback: Function]) : detox_transport.Router
Unregister event handler.

### Event: send
Payload object (all properties are `Uint8Array`):
```javascript
{node_id, packet}
```
Event is fired when `packet` needs to be sent to `node_id` node.

### Event: data
Payload object (all properties are `Uint8Array`):
```javascript
{node_id, route_id, data}
```
Event is fired when `data` were received from the responder on routing path with started at `node_id` with `route_id`.

### Event: destroyed
Payload object (all properties are `Uint8Array`):
```javascript
{node_id, route_id}
```
Event is fired when routing path started at `node_id` with `route_id` was destroyed (initiated by another side).

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

When reading LiveScript code make sure to configure 1 tab to be 4 spaces (GitHub uses 8 by default), otherwise code might be hard to read.

## License
MIT, see license.txt
