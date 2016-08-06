const net = require('net')
const nacl = require('tweetnacl')
const Wire = require('./')
// alice's long term identity key
const alice = nacl.box.keyPair()
// bob's long term identity key
const bob = nacl.box.keyPair()

const a = new Wire({
  identity: alice,
  theirIdentity: bob.publicKey
})

const b = new Wire({
  identity: bob,
  theirIdentity: alice.publicKey
})

// pipe directly:
// a.pipe(b).pipe(a)

// via TCP connection:
const aliceServer = net.createServer(function (connection) {
  a.pipe(connection).pipe(a)
})

aliceServer.listen(2345)
const bobConnection = net.connect(2345)
b.pipe(bobConnection).pipe(b)

a.send('hey!') // String|Buffer
b.on('message', function (msg) {
  console.log('alice says: ' + msg.toString())
  bobConnection.end()
  aliceServer.close()
})
