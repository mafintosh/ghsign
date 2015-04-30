# ghsign

Sign/verify data using your local ssh private key and your public key from Github

```
npm install ghsign
```

## Usage

``` js
var ghsign = require('ghsign')

// create a signer (has be your own Github username)
var sign = ghsign.signer('mafintosh')

// create a verifier (can be any Github username)
var verify = ghsign.verifier('mafintosh')

// sign some data
sign('test', function(err, sig) {
  console.log('test signature is', sig)

  // verify the signature
  verify('test', sig, function(err, valid) {
    console.log('wat test signed by mafintosh?', valid)
  })
})
```

Creating a signer will fetch your public keys from github and use your
corresponding local ssh private key to sign the data. The verifier will verify the signature by also fetching the public keys from Github.

## License

MIT
