const jwt = require('jsonwebtoken');

function currentUser(token) {
  return jwt.verify(token, process.env.JWT_KEY, { algorithms: ['none', 'HS256'] });
}
module.exports = { currentUser };
