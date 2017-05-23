/**
 * A dummy manual test script.
 */
var LdapAuth = require('./lib/ldapauth');
var Logger = require('bunyan');

var log = new Logger({
  name: 'ldapjs',
  component: 'client',
  stream: process.stderr,
  level: 'trace'
});

var opts = {
  "url": "ldap://ldap.forumsys.com:389",
  "adminDn": "cn=read-only-admin,dc=example,dc=com",
  "adminPassword": "password",
  "searchBase": "dc=example,dc=com",
  "searchFilter": "(uid={{username}})",
  "log": log
}

var a = new LdapAuth(opts);
a.on('error', function(err) {
  console.warn('Error event', err);
  a.close();
  // TODO: a.close() does not seem to do anything in case of admin
  // client bind error (e.g. use incorrect adminPassword)
});

a.authenticate('riemann', 'password', function(err, user) {
  if (err) {
    console.warn('Error', err, user);
  } else {
    console.dir(user, {depth: null});
  }
  a.close();
});
