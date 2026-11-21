const jwt = require('jsonwebtoken');

function issue(user) {
  return jwt.sign({ sub: user.id, role: user.role }, 'secret');
}
module.exports = { issue };
