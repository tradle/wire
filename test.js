
const crypto = require('crypto')
const test = require('tape')
const nacl = require('tweetnacl')
const Wire = require('./')
const names = ['alice', 'bob', 'carol']
const users = names.map(name => {
  return {
    identity: nacl.box.keyPair(),
    handshake: nacl.box.keyPair(),
    // session: new SecretSession(),
    name: name
  }
})

const alice = users[0]
const bob = users[1]
const carol = users[2]

process.on('uncaughtException', function (err) {
  console.error(err.stack)
  process.exit(1)
})

;[true, false].forEach(function (tls) {
  var testType = tls ? 'tls' : 'plaintext'
  test(`basic ${testType}`, function (t) {
    t.plan(4)

    const settings = [
      createWires(),
      createWires().reverse()
    ]

    settings.forEach(function (wires) {
      const a = wires[0]
      const b = wires[1]

      const msgs = [
        new Buffer('hey'),
        new Buffer('ho')
      ]

      b.on('message', function (data) {
        t.same(msgs.shift(), data)
      })

      a.pipe(b).pipe(a)

      msgs.forEach(function (msg) {
        a.send(msg, function (err) {
          if (err) throw err
        })
      })
    })
  })

  test(`request ${testType}`, function (t) {
    t.plan(4)

    const wires = createWires()
    const a = wires[0]
    const b = wires[1]
    a.on('error', t.error)
    b.on('error', t.error)

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

  function createWires () {
    return createWiresPair(tls)
  }
})

test('prevent impersonation', function (t) {
  t.plan(1)

  const a = new Wire({
    identity: alice.identity,
    theirIdentity: bob.identity.publicKey
  })

  const b = new Wire({
    identity: carol.identity,
    theirIdentity: alice.identity.publicKey
  })

  a.on('error', t.pass)

  const msgs = [
    new Buffer('hey'),
    new Buffer('ho')
  ]

  a.pipe(b).pipe(a)

  msgs.forEach(function (msg) {
    a.send(msg)
  })

  b.on('message', t.fail)
})

test('take calls from strangers', function (t) {
  t.plan(2)

  const a = new Wire({
    identity: alice.identity,
    theirIdentity: bob.identity.publicKey
  })

  const b = new Wire({
    identity: bob.identity
  })

  const msgs = [
    new Buffer('hey'),
    new Buffer('ho')
  ]

  b.on('handshake', function (handshake) {
    b.acceptHandshake(handshake)
  })

  b.on('message', function (data) {
    t.same(msgs.shift(), data)
  })

  a.pipe(b).pipe(a)

  msgs.forEach(function (msg) {
    a.send(msg, function (err) {
      if (err) throw err
    })
  })
})

function createWiresPair (tls) {
  if (!tls) {
    return [
      new Wire({ plaintext: true }),
      new Wire({ plaintext: true })
    ]
  }

  const a = new Wire({
    plaintext: !tls,
    identity: alice.identity,
    theirIdentity: bob.identity.publicKey
  })

  const b = new Wire({
    plaintext: !tls,
    identity: bob.identity,
    theirIdentity: alice.identity.publicKey
  })

  return [a, b]
}
