var request = require('request')
var thunky = require('thunky')
var crypto = require('crypto')
var fs = require('fs')
var path = require('path')
var SSHAgentClient = require('ssh-agent')
var sshKeyToPEM = require('ssh-key-to-pem')

var readSync = function(file) {
  try {
    return fs.readFileSync(file)
  } catch (err) {
    return null
  }
}

var HOME = process.env.HOME || process.env.USERPROFILE
var DEFAULT_SSH_KEY = readSync(path.join(HOME, '.ssh/id_rsa')) || readSync(path.join(HOME, '.ssh/id_dsa'))

var toPEM = function(key) {
  if (Buffer.isBuffer(key)) key = key.toString()
  return key.indexOf('-----BEGIN ') > -1 ? key : sshKeyToPEM(key)
}

var isPublicKey = function(key) {
  return key.indexOf('-----BEGIN PUBLIC KEY-----') === 0
}

var githubPublicKeys = function(username, cb) {
  request('https://github.com/'+username+'.keys', function(err, response) {
    if (err) return cb(err)
    if (response.statusCode !== 200) return cb(new Error('Public keys for '+username+' not found'))

    cb(null, response.body.trim().split('\n').map(toPEM))
  })
}

var signer = function(username, keys) {
  if (username && username.indexOf('\n') > -1) return signer(null, username)
  keys = [].concat(keys || []).map(toPEM)

  var privateKey = keys.length && !isPublicKey(keys[0]) && keys[0]
  var publicKeys = keys.length && keys.every(isPublicKey) && keys

  if (!process.env.SSH_AUTH_SOCK && !privateKey) privateKey = DEFAULT_SSH_KEY

  if (privateKey) {
    if (privateKey.indexOf('ENCRYPTED') > -1) throw new Error('Encrypted keys not supported. Setup an SSH agent or decrypt it first')
    return function(data, cb) {
      process.nextTick(function() {
        cb(null, crypto.createSign('RSA-SHA1').update(data).sign(privateKey, 'base64'))
      })
    }
  }

  var client = new SSHAgentClient()
  var pks = publicKeys ?
    function(cb) {
      cb(null, publicKeys)
    } :
    function(cb) {
      githubPublicKeys(username, cb)
    }

  var detectPublicKey = thunky(function(cb) {
    pks(function(err, pubs) {
      if (err) return cb(err)

      client.requestIdentities(function(err, keys) {
        if (err) return cb(err)

        var key = keys.reduce(function(result, key) {
          return result || pubs.indexOf(toPEM(key.type+' '+key.ssh_key)) > -1 && key
        }, null)

        if (!key) return cb(new Error('No corresponding local SSH private key found for '+username))

        cb(null, key)
      })
    })
  })

  return function(data, cb) {
    if (typeof data === 'string') data = new Buffer(data)

    detectPublicKey(function(err, key) {
      if (err) return cb(err)

      client.sign(key, data, function(err, sig) {
        if (err) return cb(err)

        cb(null, sig.signature)
      })
    })
  }
}

var verifier = function(username) {
  var pks = thunky(function(cb) {
    githubPublicKeys(username, cb)
  })

  return function(data, sig, cb) {
    if (!sig) return cb(null, false)

    pks(function(err, pubs) {
      if (err) return cb(err)

      var verified = pubs.some(function(key) {
        return crypto.createVerify('RSA-SHA1').update(data).verify(key, sig, 'base64')
      })

      cb(null, verified)
    })
  }
}

exports.publicKeys = githubPublicKeys
exports.verifier = verifier
exports.signer = signer