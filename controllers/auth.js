const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET
} = require('../env_exports');

// a function to handle user login
const handleLogin = async (req, res) => {
  // Extract the username and password from the request body
  const { user, pwd } = req.body;
  // Check if both username and password are provided, return a 400 Bad Request if not 
  if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });
  // Find a user with the provided username in the database
  const foundUser = await User.findOne({ username: user }).exec();
  // If no user is found, return a 401 Unauthorized response
  if (!foundUser) return res.sendStatus(401);
  // Compare the provided password with the hashed password stored in the database
  const passwordMatch = await bcrypt.compare(pwd, foundUser.password);
  // If the passwords match, proceed with generating tokens and sending the response
  if (passwordMatch) {
    // Extract non-false values from the user's roles
    const roles = Object.values(foundUser.roles).filter(Boolean);
    // Create an access token with user information and roles
    const accessToken = jwt.sign(
      {
        "UserInfo": {
          "username": foundUser.username,
          "roles": roles
        }
      },
      ACCESS_TOKEN_SECRET,
      { expiresIn: '10s' }
    );
    // Create a refresh token with the username
    const refreshToken = jwt.sign(
      { "username": foundUser.username },
      REFRESH_TOKEN_SECRET,
      { expiresIn: '1d' }
    );
    // Save the refresh token with the current user in the database
    foundUser.refreshToken = refreshToken;
    const result = await foundUser.save();
    // Log the result and user roles (for debugging purposes)
    console.log(result);
    console.log(roles);

    // Create a secure HTTP-only cookie to store the refresh token (validity 1 day)
    res.cookie('jwt', refreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

    // Send authorization roles and access token in the response
    res.json({ roles, accessToken });

  } else {
    // If passwords don't match, return a 401 Unauthorized response
    res.sendStatus(401);
  }
}

module.exports = { handleLogin };