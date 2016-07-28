
const crypto = require('crypto')
const inherits = require('util').inherits
const increment = require('increment-buffer')
const lps = require('length-prefixed-stream')
const debug = require('debug')('tradle:wire')
const stream = require('readable-stream')
const Duplex = stream.Duplex
const duplexify = require('duplexify')
const bindAll = require('bindAll')
const schema = require('./schema')
const noop = function () {}
const ENCODERS = [
  schema.Open,
  schema.Handshake,
  schema.Request,
  schema.Data,
  schema.Ack
]

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

  // Duplex.call(this)

  duplexify.call(this)
  bindAll(this)

  // this._them = opts.them
  this._ack = opts.ack || 0
  this._sign = opts.sign
  this._verify = opts.verify
  this._debugId = INSTANCE_ID++
  this._encode = lps.encode()
  this._decode = lps.decode()
  this._decode.on('data', function (data) {
    self._receive(data)
  })

  this._nonce = crypto.randomBytes(32)
  this.setReadable(this._encode)
  this.setWritable(this._decode)
  this._outgoing = []
  this._incoming = []
  // set to `true` when the counterparty
  // has authenticated themselves to us
  this._authenticated = false
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

Wire.prototype._message = function (type, message) {
  if (this.destroyed) return false

  const enc = ENCODERS[type]
  const len = enc ? enc.encodingLength(message) : 0
  const buf = Buffer(len + 1)

  buf[0] = type
  if (enc) enc.encode(message, buf, 1)

  // if (this.private) buf = this._encrypt(channel, buf)

  this._debug('sending ' + keyByValue(schema, enc))
  return this._encode.write(buf)
}

Wire.prototype._read = function () {}

Wire.prototype._receive = function (buf) {
  this._incoming.push(buf)
  this._processIncoming()
}

Wire.prototype._processIncoming = function () {
  const self = this
  if (this._processingIncoming || !this._incoming.length) return

  const buf = this._processingIncoming = this._incoming.shift()
  const type = buf[0]
  const enc = ENCODERS[type]
  if (!enc) return this.destroy(new Error('received invalid data'))

  this._debug('received ' + keyByValue(schema, enc))

  try {
    var msg = enc.decode(buf, 1)
  } catch (err) {
    return this.destroy(err)
  }

  if ('ack' in msg) this._receiveAck(msg)

  switch (type) {
  case 0: return this._onopen(msg, postProcess)
  case 1: return this._onhandshake(msg, postProcess)
  case 2: return this._onrequest(msg, postProcess)
  case 3: return this._ondata(msg, postProcess)
  case 4: return postProcess()
  }

  function postProcess () {
    self._processingIncoming = null
    self._processIncoming()
  }
}

Wire.prototype.open = function () {
  this._initiator = true
  if (!this._ourChallenge) this._ourChallenge = copyBuf(this._nonce)

  this._message(0, {
    nonce: this._nonce
  })
}

Wire.prototype._maybeOpen = function () {
  if (this._initiator == null) this.open()
}

Wire.prototype.handshake = function (open, cb) {
  const self = this
  cb = cb || noop

  if (!this._ourChallenge) this._ourChallenge = copyBuf(this._nonce)

  this._sign(Buffer.concat([open.nonce, this._ourChallenge]), function (err, sig) {
    if (err) {
      self.emit('error', err)
      return cb(err)
    }

    self._message(1, {
      nonce: self._ourChallenge,
      sig: sig,
      ack: self._ack
    })

    cb()
  })
}

Wire.prototype.request = function (seq) {
  this._queueOutgoing(2, {
    seq: seq
  })
}

Wire.prototype.send = function (msg) {
  this._queueOutgoing(3, {
    ack: this._ack,
    payload: msg
  })
}

/**
 * specify the last message we've received
 */
Wire.prototype.ack = function (ack) {
  if (ack === 0) throw new Error('ack must be a positive integer')

  this._ack = ack
  if (this._outgoing.length) return // ack in next outgoing message

  this._queueOutgoing(4, {
    ack: ack
  })
}

Wire.prototype._queueOutgoing = function (type, msg) {
  this._outgoing.push(arguments)
  this._maybeOpen()
  if (this._authenticated) {
    this._processOutgoing()
  }
}

Wire.prototype._onopen = function (open, cb) {
  if (this._initiator) return this.destroy(new Error('resigning as initiator'))

  this._initiator = false
  this.handshake(open, cb)
}

Wire.prototype._onhandshake = function (handshake, cb) {
  const self = this
  const data = Buffer.concat([this._ourChallenge, handshake.nonce])

  this._verify(data, handshake.sig, function (err) {
    if (err) {
      self._debug('invalid signature received on handshake')
      return cb()
    }

    self._debug('authenticated')
    self._authenticated = true
    self.emit('open')
    if (self._initiator) {
      self.handshake(handshake, self._processOutgoing)
    } else {
      self._processOutgoing()
    }

    cb()
  })
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

Wire.prototype._processOutgoing = function () {
  if (!this._authenticated) return

  const args = this._outgoing.shift()
  if (args) {
    this._message.apply(this, args)
    this._processOutgoing()
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
