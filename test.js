
const crypto = require('crypto')
const test = require('tape')
const Wire = require('./')

test('basic', function (t) {
  t.plan(2)

  const a = fakeWire()
  const b = fakeWire()
  const msgs = [
    new Buffer('hey'),
    new Buffer('ho')
  ]

  b.on('message', function (data) {
    t.same(msgs.shift(), data)
  })

  a.pipe(b).pipe(a)

  msgs.forEach(function (msg) {
    a.send(msg)
  })
})

test('request', function (t) {
  t.plan(4)

  const a = fakeWire()
  const b = fakeWire()
  const msgs = [
    { seq: 1, msg: new Buffer('hey') },
    { seq: 2, msg: new Buffer('ho') }
  ]

  a.pipe(b).pipe(a)

  a.on('request', function (seq) {
    const msg = msgs.filter(function (msg) {
      return msg.seq === seq
    })[0]

    a.send(msg.msg)
  })

  b.request(2)
  b.once('message', function (msg) {
    b.ack(2)
    t.same(msg, msgs[1].msg)
    b.request(1)
    b.once('message', function (msg) {
      b.ack(1)
      t.same(msg, msgs[0].msg)
    })
  })

  const expectedAcks = [2, 1]
  a.on('ack', function (ack) {
    t.equal(ack, expectedAcks.shift())
  })
})

function fakeWire (them) {
  return new Wire({
    sign: fakeSign,
    verify: fakeVerify,
    ack: 0
  })
}

function fakeSign (data, cb) {
  process.nextTick(function () {
    cb(null, sha256(data))
  })
}

function fakeVerify (data, sig, cb) {
  fakeSign(data, function (err, expected) {
    if (sig.equals(expected)) return cb()

    cb(new Error('invalid sig'))
  })
}

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}
