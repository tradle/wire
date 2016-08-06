# Usage

work in progress!  

uses [alax/forward-secrecy](https://github.com/alax/forward-secrecy)

```js
const nacl = require('tweetnacl')
const Wire = require('@tradle/wire')
const alice = nacl.box.keyPair()
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
```

Todo:

Save and reuse sessions. Ccurrently a new session is established each time.
