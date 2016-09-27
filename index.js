
const inherits = require('util').inherits
const lps = require('length-prefixed-stream')
const through = require('through2')
const pump = require('pump')
const debug = require('debug')('tradle:wire')
const stream = require('readable-stream')
const Duplex = stream.Duplex
const duplexify = require('duplexify')
const bindAll = require('bindall')
const Session = require('forward-secrecy')
const nacl = require('tweetnacl')
const schema = require('./schema')
const noop = function () {}
const ENCODERS = {
  envelope: [
    schema.Handshake,
    schema.Encrypted,
  ],
  payload: [
    schema.Request,
    schema.Data,
    schema.Ack
  ]
}

module.exports = exports = Wire
exports.nacl = nacl

/**
 * flow:
 *
 * A                    B
 *      --> open
 *      <-- handshake
 *      --> handshake
 *      <--> data/ack
 */

var INSTANCE_ID = 0

function Wire (opts) {
  const self = this
  if (!(this instanceof Wire)) return new Wire(opts)

  bindAll(this)
  duplexify.call(this)

  this._debugId = INSTANCE_ID++
  this._encode = lps.encode()
  this._decode = lps.decode()
  this.setReadable(this._encode)
  this.setWritable(this._decode)

  var pipeline = [ this._decode ]
  this._plaintext = !!opts.plaintext
  this._authenticated = this._plaintext
  if (!this._plaintext) {
    this._identityKey = normalizePrivKey(opts.identity)
    this._handshakeKey = normalizePrivKey(opts.handshake || nacl.box.keyPair())
    this._session = new Session()
      .identity(this._identityKey)
      .handshake(this._handshakeKey)

    if (opts.theirIdentity) this._setTheirIdentity(opts.theirIdentity)

    pipeline.push(through.obj(processEnvelope))

    this._debug('identity', this._identityKey.publicKey.toString('hex'))
    this._debug('handshake', this._handshakeKey.publicKey.toString('hex'))
  }

  this._ack = opts.ack || 0

  pipeline.push(through.obj(processPayload))
  pump(pipeline)

  // set to `true` when the counterparty
  // has authenticated themselves to us

  function processEnvelope (data, enc, cb) {
    try {
      var payload = decodeEnvelope(data)
    } catch (err) {
      self._debug('skipping message with invalid envelope', data)
      return cb()
    }

    switch (data[0]) {
    case 0:
      return self._onhandshake(payload, function (err) {
        if (err) self._debug('failed to process handshake', payload, err)
        cb()
      })
    case 1:
      return self._session.decrypt(payload)
        .then(function (result) {
          const payload = new Buffer(result.cleartext, 'base64')
          cb(null, payload)
        }, function (err) {
          self._debug('failed to decrypt message', payload, err)
          cb()
        })
        .catch(function (err) {
          self._debug('error processing message', payload, err)
          cb()
        })
    default:
      return cb()
    }
  }

  function processPayload (payload, enc, cb) {
    try {
      var msg = decodePayload(payload)
    } catch (err) {
      self._debug('skipping message with invalid payload', payload)
      return cb(err)
    }

    self._receiveAck(msg)
    self._debug('received ' + (payload[0] === 0 ? 'request' : payload[0] === 1 ? 'data' : 'ack'))

    switch (payload[0]) {
    case 0: return self._onrequest(msg, cb)
    case 1: return self._ondata(msg, cb)
    default: cb()
    }
  }
}

inherits(Wire, duplexify)

Wire.prototype.end = function () {
  this._debug('end')
  Duplex.prototype.end.apply(this, arguments)
}

Wire.prototype.destroy = function (err) {
  if (this.destroyed) return
  this.destroyed = true
  this._debug('destroy', err)
  this.emit('close')
  this.end()
}

Wire.prototype._debug = function () {
  var args = [].slice.call(arguments)
  args[0] = '[' + this._debugId + '] ' + args[0]
  debug.apply(null, args)
}

Wire.prototype._read = function () {}

Wire.prototype.open = function () {
  this._initiator = true
  this.handshake()
}

Wire.prototype._maybeOpen = function () {
  if (this._initiator == null) this.open()
}

Wire.prototype._setTheirIdentity = function (theirIdentity) {
  theirIdentity = normalizePubKey(theirIdentity)
  if (this._theirIdentityKey && !theirIdentity.equals(this._theirIdentityKey)) {
    throw new Error('refusing to change to a different counterparty')
  }

  this._theirIdentityKey = theirIdentity
  const role = getRole(this._identityKey.publicKey, this._theirIdentityKey)
  this._debug('role: ' + role)

  this._session
    .theirIdentity(this._theirIdentityKey)
    .setRole(role)
}

Wire.prototype.handshake = function () {
  this._debug('sending handshake')
  this._sendEnvelope(0, {
    ephemeralKey: new Buffer(this._handshakeKey.publicKey),
    staticKey: new Buffer(this._identityKey.publicKey),
    authenticated: this._authenticated
  }, true)
}

Wire.prototype._send = function (tag, data) {
  var method = this._plaintext ? '_sendCleartext' : '_sendEncrypted'
  this[method](tag, data)
}

Wire.prototype.request = function (seq) {
  this._send(0, {
    seq: seq
  })
}

Wire.prototype.send = function (msg, cb) {
  this._send(1, {
    ack: this._ack,
    payload: msg
  }, cb)
}

/**
 * specify the last message we've received
 */
Wire.prototype.ack = function (ack) {
  if (ack === 0) throw new Error('ack must be a positive integer')

  this._ack = ack
  // TODO: include acks in other message
  // if (this._outgoing.length) return // ack in next outgoing message

  this._send(2, {
    ack: ack
  })
}

Wire.prototype._onhandshake = function (handshake, cb) {
  if (this._authenticated && handshake.authenticated) {
    return nextTick(cb)
  }

  this._debug('received handshake')
  if (this._theirIdentityKey) {
    if (!handshake.staticKey.equals(this._theirIdentityKey)) {
      // console.log('their identity', handshake.staticKey.toString('hex'))
      // console.log('their handshake', handshake.ephemeralKey.toString('hex'))
      this._debug('ignoring handshake from a different identity')
      this.emit('error', new Error('invalid handshake'))
      return cb()
    }

    return this.acceptHandshake(handshake, cb)
  }

  this.emit('handshake', handshake)
  cb()
}

Wire.prototype.acceptHandshake = function (handshake, cb) {
  const self = this
  cb = cb || noop

  this._setTheirIdentity(handshake.staticKey)
  this._session
    .theirHandshake(handshake.ephemeralKey)
    .computeMasterKey()
    .then(function () {
      self._debug('authenticated')
      self._authenticated = true
      self.emit('open')
      // if (self._initiator) self.handshake()

      // TODO: optimize to avoid double-sending handshake
      if (!handshake.authenticated) self.handshake()

      cb()
    }, cb)
}

Wire.prototype._sendCleartext = function (type, msg) {
  const buf = encodePayload(type, msg)
  this._encode.write(buf)
}

Wire.prototype._sendEnvelope = function (type, msg) {
  // this._debug('sending', type === 0 ? 'handshake' : 'encrypted data')
  const encoded = encodeEnvelope(type, msg)
  this._encode.write(encoded)
}

Wire.prototype._sendEncrypted = function (type, msg, cb) {
  const self = this
  if (!this._authenticated) {
    this._maybeOpen()
    return this.once('open', function () {
      self._send(type, msg, cb)
    })
  }

  this._debug('sending', keyByValue(schema, ENCODERS.payload[type]))
  const buf = encodePayload(type, msg)
  this._session.encrypt(buf.toString('base64')).then(function (result) {
    self._sendEnvelope(1, result)
    cb()
  }, cb)
}

Wire.prototype._ondata = function (msg, cb) {
  if (!this._authenticated) return this.destroy(new Error('did not receive handshake'))

  this.emit('message', msg.payload)
  cb()
}

Wire.prototype._onrequest = function (msg, cb) {
  if (!this._authenticated) return this.destroy(new Error('did not receive handshake'))

  this.emit('request', msg.seq)
  cb()
}

Wire.prototype._receiveAck = function (msg) {
  // ignore ack 0
  if (msg.ack) {
    this.emit('ack', msg.ack)
  }
}

function copyBuf (buf, offset) {
  const copy = new Buffer(buf.length)
  buf.copy(copy, 0, offset)
  return copy
}

function keyByValue (obj, val) {
  for (var p in obj) {
    if (obj[p] === val) return p
  }
}

function nextTick (fn, arg1, arg2) {
  process.nextTick(function () {
    fn(arg1, arg2)
  })
}

function encodeEnvelope (type, msg) {
  return encode(ENCODERS.envelope, type, msg)
}

function encodePayload (type, msg) {
  return encode(ENCODERS.payload, type, msg)
}

function decodeEnvelope (data) {
  return decode(ENCODERS.envelope, data)
}

function decodePayload (data) {
  return decode(ENCODERS.payload, data)
}

function encode (encoders, type, msg) {
  for (var p in msg) {
    var val = msg[p]
    if (val instanceof Uint8Array) {
      msg[p] = new Buffer(val)
    }
  }

  const enc = encoders[type]
  const len = enc ? enc.encodingLength(msg) : 0
  const buf = new Buffer(len + 1)

  buf[0] = type
  enc.encode(msg, buf, 1)
  return buf
}

function decode (encoders, data) {
  const type = data[0]
  const enc = encoders[type]
  return enc.decode(data, 1)
}

function normalizePrivKey (key) {
  if (key.secretKey) {
    return {
      secretKey: toBuffer(key.secretKey),
      publicKey: toBuffer(key.publicKey)
    }
  }

  return nacl.box.keyPair.fromSecretKey(toBuffer(key))
}

function normalizePubKey (key) {
  if (key.publicKey) return key.publicKey

  return toBuffer(key)
}

function toBuffer (buf) {
  if (Buffer.isBuffer(buf)) return buf
  if (buf instanceof Uint8Array) return new Buffer(buf)

  throw new Error('expected Buffer or Uint8Array')
}

function getRole (us, them) {
  for (var i = 0; i < us.length; i++) {
    if (us[i] === them[i]) continue
    if (us[i] > them[i]) {
        return 'initiator'
    } else {
        return 'receiver'
    }

    break
  }
}
