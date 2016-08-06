
const inherits = require('util').inherits
const lps = require('length-prefixed-stream')
const through = require('through2')
const pump = require('pump')
const debug = require('debug')('tradle:wire')
const stream = require('readable-stream')
const Duplex = stream.Duplex
const duplexify = require('duplexify')
const bindAll = require('bindAll')
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

module.exports = Wire

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

  this._identityKey = normalizeKey(opts.identity)
  this._theirIdentityKey = normalizeKey(opts.theirIdentity)
  this._handshakeKey = normalizeKey(opts.handshake || nacl.box.keyPair())


  bindAll(this)
  duplexify.call(this)

  this._ack = opts.ack || 0
  const role = getRole(this._identityKey.publicKey, this._theirIdentityKey)
  this._session = new Session()
    .identity(this._identityKey)
    .handshake(this._handshakeKey)
    .theirIdentity(this._theirIdentityKey)
    .setRole(role)

  this._debugId = INSTANCE_ID++
  this._debug('role: ' + role)

  this._encode = lps.encode()
  this._decode = lps.decode()
  pump(
    this._decode,
    through.obj(processEnvelope),
    through.obj(processPayload)
  )

  this.setReadable(this._encode)
  this.setWritable(this._decode)

  // set to `true` when the counterparty
  // has authenticated themselves to us
  this._authenticated = false

  function processEnvelope (data, enc, cb) {
    try {
      var payload = decodeEnvelope(data)
    } catch (err) {
      self._debug('skipping message with invalid envelope', data)
      return cb()
    }

    switch (data[0]) {
    case 0: return self._onhandshake(payload, cb)
    case 1: return cb(null, payload)
    }
  }

  function processPayload (data, enc, cb) {
    data = denormalizeEncrypted(data)
    self._session.decrypt(data).then(function (result) {
      const payload = new Buffer(result.cleartext, 'base64')
      try {
        var msg = decodePayload(payload)
      } catch (err) {
        self._debug('skipping message with invalid payload', data)
        return cb(err)
      }

      self._receiveAck(msg)
      self._debug('received ' + (payload[0] === 0 ? 'request' : payload[0] === 1 ? 'data' : 'ack'))

      switch (payload[0]) {
      case 0: return self._onrequest(msg, cb)
      case 1: return self._ondata(msg, cb)
      default: cb()
      }
    }, cb)
    // .catch(console.error)
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

Wire.prototype.handshake = function (handshake) {
  this._debug('sending handshake')
  this._sendCleartext(0, {
    ephemeralKey: new Buffer(this._handshakeKey.publicKey),
    staticKey: new Buffer(this._identityKey.publicKey)
  }, true)
}

Wire.prototype.request = function (seq) {
  this._sendEncrypted(0, {
    seq: seq
  })
}

Wire.prototype.send = function (msg, cb) {
  this._sendEncrypted(1, {
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

  this._sendEncrypted(2, {
    ack: ack
  })
}

Wire.prototype._onhandshake = function (handshake, cb) {
  const self = this
  if (this._authenticated) return nextTick(cb)

  if (!handshake.staticKey.equals(this._theirIdentityKey)) {
    this._debug('ignoring handshake from a different identity')
    this.emit('error', new Error('invalid handshake'))
    return cb()
  }

  this._debug('received handshake')
  this._session
    .theirHandshake(handshake.ephemeralKey)
    .computeMasterKey()
    .then(function () {
      self._debug('authenticated')
      self._authenticated = true
      self.emit('open')
      // if (self._initiator) self.handshake()

      // TODO: optimize to avoid double-sending handshake
      self.handshake()

      cb()
    }, cb)
}

Wire.prototype._sendCleartext = function (type, msg) {
  // this._debug('sending', type === 0 ? 'handshake' : 'encrypted data')
  const encoded = encodeEnvelope(type, msg)
  this._encode.write(encoded)
}

Wire.prototype._sendEncrypted = function (type, msg, cb) {
  const self = this
  if (!this._authenticated) {
    this._maybeOpen()
    return this.once('open', function () {
      self._sendEncrypted(type, msg, cb)
    })
  }

  this._debug('sending', keyByValue(schema, ENCODERS.payload[type]))
  const buf = encodePayload(type, msg)
  this._session.encrypt(buf.toString('base64')).then(function (result) {
    self._sendCleartext(1, normalizeEncrypted(result))
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
  const enc = encoders[type]
  const len = enc ? enc.encodingLength(msg) : 0
  const buf = Buffer(len + 1)

  buf[0] = type
  enc.encode(msg, buf, 1)
  return buf
}

function decode (encoders, data) {
  const type = data[0]
  const enc = encoders[type]
  return enc.decode(data, 1)
}

function normalizeEncrypted (result) {
  return {
    ephemeralKey: new Buffer(result.ephemeralKey, 'base64'),
    counter: result.counter,
    previousCounter: result.previousCounter,
    ciphertext: new Buffer(result.ciphertext, 'base64'),
    nonce: new Buffer(result.nonce, 'base64')
  }
}

function denormalizeEncrypted (result) {
  return {
    ephemeralKey: result.ephemeralKey.toString('base64'),
    counter: result.counter,
    previousCounter: result.previousCounter,
    ciphertext: result.ciphertext.toString('base64'),
    nonce: result.nonce.toString('base64')
  }
}

function normalizeKey (key) {
  if (key.secretKey) {
    return {
      secretKey: toBuffer(key.secretKey),
      publicKey: toBuffer(key.publicKey)
    }
  }

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
