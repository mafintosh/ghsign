var username = 'mafintosh' // change this to your github username
var ghsign = require('./')

var sign = ghsign.signer(username)
var verify = ghsign.verifier(username)

sign('hello', function(err, sig) {
  if (err) throw err
  verify('hello', sig, function(err, valid) {
    if (err) throw err
    console.log('hello was signed by '+username+'? '+valid)
  })
})