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
var CACHE = path.join(HOME, '.cache')
var DEFAULT_SSH_KEY = readSync(path.join(HOME, '.ssh/id_rsa')) || readSync(path.join(HOME, '.ssh/id_dsa'))
var SSH_AUTH_SOCK = !!process.env.SSH_AUTH_SOCK

var create = function (fetchKey) {
  var toPEM = function(key) {
    if (Buffer.isBuffer(key)) key = key.toString()
    return key.indexOf('-----BEGIN ') > -1 ? key : sshKeyToPEM(key)
  }

  var isPublicKey = function(key) {
    return key.indexOf('-----BEGIN PUBLIC KEY-----') === 0
  }

  var githubPublicKeys = function(username, cb) {
    fetchKey(username, function (err, keys) {
      if (err) return cb(err)
      cb(null, keys.trim().split('\n').map(toPEM))
    })
  }

  var signer = function(username, keys) {
    if (username && username.indexOf('\n') > -1) return signer(null, username)
    keys = [].concat(keys || []).map(toPEM)

    var privateKey = keys.length && !isPublicKey(keys[0]) && keys[0]
    var publicKeys = keys.length && keys.every(isPublicKey) && keys
    var encrypted = false

    if (!SSH_AUTH_SOCK && !privateKey) privateKey = DEFAULT_SSH_KEY

    if (privateKey) {
      if (privateKey.toString().indexOf('ENCRYPTED') > -1) encrypted = true
      return function sign(data, enc, cb) {
        if (typeof enc === 'function') return sign(data, null, enc)
        process.nextTick(function() {
          if (encrypted) return cb(new Error('Encrypted keys not supported. Setup an SSH agent or decrypt it first'))
          cb(null, crypto.createSign('RSA-SHA224').update(data).sign(privateKey, enc))
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
      var oncache = function(cache, cb) {
        client.requestIdentities(function(err, keys) {
          if (err) return cb(err)

          var key = keys.reduce(function(result, key) {
            return result || (key.type === cache.type && key.ssh_key === cache.ssh_key && key)
          }, null)

          if (!key) return onnocache(cb)
          cb(null, key)
        })
      }

      var onnocache = function(cb) {
        pks(function(err, pubs) {
          if (err) return cb(err)

          client.requestIdentities(function(err, keys) {
            if (err) return cb(err)

            var key = keys.reduce(function(result, key) {
              return result || (pubs.indexOf(toPEM(key.type+' '+key.ssh_key)) > -1 && key)
            }, null)

            if (!key && SSH_AUTH_SOCK && DEFAULT_SSH_KEY) {
              SSH_AUTH_SOCK = false
              return cb(null, null)
            }

            if (!key) return cb(new Error('No corresponding local SSH private key found for '+username))

            fs.mkdir(CACHE, function() {
              fs.writeFile(path.join(CACHE, 'ghsign.json'), JSON.stringify({username:username, type:key.type, ssh_key:key.ssh_key}), function() {
                cb(null, key)
              })
            })
          })
        })
      }

      fs.readFile(path.join(CACHE, 'ghsign.json'), 'utf-8', function(err, data) {
        if (!data) return onnocache(cb)
        try {
          data = JSON.parse(data)
        } catch (err) {
          return oncache(cb)
        }
        if (data.username !== username) return onnocache(cb)
        oncache(data, cb)
      })
    })

    var cachedSign

    return function sign(data, enc, cb) {
      if (typeof enc === 'function') return sign(data, null, enc)
      if (typeof data === 'string') data = new Buffer(data)
      if (cachedSign) return cachedSign(data, enc, cb)

      detectPublicKey(function(err, key) {
        if (err) return cb(err)
        if (key === null) {
          cachedSign = signer(username)
          return sign(data, enc, cb)
        }

        client.sign(key, data, function(err, sig) {
          if (err) return cb(err)

          if (enc === 'base64') return cb(null, sig.signature)
          var buf = new Buffer(sig.signature, 'base64')
          if (enc) buf = buf.toString(enc)
          cb(null, buf)
        })
      })
    }
  }

  var verifier = function(username) {
    var pks = thunky(function(cb) {
      githubPublicKeys(username, cb)
    })

    return function verify(data, sig, enc, cb) {
      if (typeof enc === 'function') return verify(data, sig, null, enc)
      if (!sig) return cb(null, false)

      pks(function(err, pubs) {
        if (err) return cb(err)

        var verified = pubs.some(function(key) {
          return crypto.createVerify('RSA-SHA224').update(data).verify(key, sig, enc)
        })

        cb(null, verified)
      })
    }
  }

  var exports = {}

  exports.publicKeys = githubPublicKeys
  exports.verifier = verifier
  exports.signer = signer

  return exports
}

var defaults = create(function (username, cb) {
  request('https://github.com/'+username+'.keys', {timeout: 30000}, function(err, response) {
    if (err) return cb(err)
    if (response.statusCode !== 200) return cb(new Error('Public keys for '+username+' not found'))
    cb(null, response.body)
  })
})

module.exports = create
create.signer = defaults.signer
create.verifier = defaults.verifier
create.publicKeys = defaults.publicKeys
