const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const authHeader = req.get('Authorization');
  if (!authHeader) {
    req.isAuth = false;
    return next();
  }
  const token = authHeader.split(' ')[1];
  let decodedToken;
  try {
    decodedToken = jwt.verify(token, 'graphqlsecret');
  } catch (err) {
    req.isAuth = false;
    next();
  }
  if (!decodedToken) {
    req.isAuth = false;
    next();
  }
  req.userId = decodedToken.userId;
  req.isAuth = true;
  next();
};
