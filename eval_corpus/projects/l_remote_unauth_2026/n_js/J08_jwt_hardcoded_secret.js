const jwt = require('jsonwebtoken');

function issue(user) {
  return jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_KEY, { expiresIn: '1h' });
}
module.exports = { issue };
