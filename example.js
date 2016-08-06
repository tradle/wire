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

a.pipe(b).pipe(a)

a.send('hey!') // String|Buffer
b.on('message', function (msg) {
  console.log(msg.toString()) // should print 'hey'
})
