const jwt = require('jsonwebtoken');

// Middleware function to verify JWT (JSON Web Token)
const verifyJWT = (req, res, next) => {
  // Check if the 'Authorization' header is present and starts with 'Bearer'
  const authHeader = req.headers.authorization || req.headers.Authorization;
  // If not, return a 401 Unauthorized response
  if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
  // Extract the token from the 'Authorization' header
  const token = authHeader.split(' ')[1];
  // Verify the token using the provided secret key
  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET,
    (err, decoded) => {
      // If token verification fails, return a 403 Forbidden response (invalid token)
      if (err) return res.sendStatus(403);
      // If the token is valid, store user information and roles in the request object
      req.user = decoded.UserInfo.username;
      req.roles = decoded.UserInfo.roles;
      // Continue with the next middleware or route handler
      next();
    }
  );
}
// Export the verifyJWT middleware
module.exports = verifyJWT