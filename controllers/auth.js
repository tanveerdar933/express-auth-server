const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET
} = require('../env_exports');


const register = async (req, res) => {
  const { user, pwd } = req.body;
  console.log("register: ", user, pwd);
  if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });

  // check for duplicate usernames in the db
  const duplicate = await User.findOne({ username: user }).exec();
  if (duplicate) return res.sendStatus(409); //Conflict 

  try {
    //encrypt the password
    const hashedPwd = await bcrypt.hash(pwd, 10);

    //create and store the new user
    const result = await User.create({
      "username": user,
      "password": hashedPwd
    });

    res.status(201).json({ 'success': `New user ${user} created!` });
  } catch (err) {
    res.status(500).json({ 'message': err.message });
  }
}


// a function to handle user login
const login = async (req, res) => {
  const cookies = req.cookies;
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
    let newRefreshToken = jwt.sign(
      { "username": foundUser.username },
      REFRESH_TOKEN_SECRET,
      { expiresIn: '1d' }
    );

    const newRefreshTokenArray =
      !cookies?.jwt
        ? foundUser.refreshToken
        : foundUser.refreshToken.filter(rt => rt !== cookies.jwt);

    if (cookies?.jwt) {
      /*
        1. User logs in but never uses refresh token and does not logout
        2. Refresh token is stolen
        3. if 1 & 2, reuse detection is needed to clear all RTs when user logs in 
       */

      const refreshToken = cookies.jwt;
      const foundToken = await User.findOne({ refreshToken }).exec();

      //Detected refresh token reuse!
      if (!foundToken) {
        console.log('attempted refresh token reuse at login!');
        //clear out all previous refresh tokens
        newRefreshTokenArray = [];
      }
      res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    }

    // Save the refresh token with the current user in the database
    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
    await foundUser.save();

    // Create a secure HTTP-only cookie to store the refresh token (validity 1 day)
    res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

    // Send authorization roles and access token in the response
    res.json({ roles, accessToken });

  } else {
    // If passwords don't match, return a 401 Unauthorized response
    res.sendStatus(401);
  }
}


const refreshToken = async (req, res) => {
  // Retrieve cookies from the request
  const cookies = req.cookies;
  // If no 'jwt' cookie is found, return a 401 Unauthorized response
  if (!cookies?.jwt) return res.sendStatus(401);
  // Extract the refresh token from the 'jwt' cookie
  const refreshToken = cookies.jwt;
  // Delete the cookie after token extraction
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
  // Find a user associated with the provided refresh token
  const foundUser = await User.findOne({ refreshToken }).exec();
  // Detect refresh token reuse!
  if (!foundUser) {
    jwt.verify(
      refreshToken,
      REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err) return res.sendStatus(403); //Forbidden
        const hackedUser = await User.findOne({ username: decoded.username }).exec();
        hackedUser.refreshToken = [];
        const result = await hackedUser.save();
        console.log(result);
      }
    )
    return res.sendStatus(403); //Forbidden 
  }
  const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken);

  // evaluate jwt 
  jwt.verify(
    refreshToken,
    REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      //if refresh token expired
      if (err) {
        foundUser.refreshToken = [...newRefreshTokenArray];
        const result = await foundUser.save();
      }
      if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
      //if refresh token is still valid
      const roles = Object.values(foundUser.roles);
      const accessToken = jwt.sign(
        {
          "UserInfo": {
            "username": decoded.username,
            "roles": roles
          }
        },
        ACCESS_TOKEN_SECRET,
        { expiresIn: '10s' }
      );

      // Create a refresh token with the username
      const newRefreshToken = jwt.sign(
        { "username": foundUser.username },
        REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
      );
      // Save the refresh token with the current user in the database
      foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
      await foundUser.save();

      // Create a secure HTTP-only cookie to store the refresh token (validity 1 day)
      res.cookie('jwt', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });

      res.json({ roles, accessToken })
    }
  );
}

const logout = async (req, res) => {
  // On client, also delete the accessToken

  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  const refreshToken = cookies.jwt;

  // Is refreshToken in db?
  const foundUser = await User.findOne({ refreshToken }).exec();
  if (!foundUser) {
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    return res.sendStatus(204);
  }

  // Delete refreshToken in db
  foundUser.refreshToken = foundUser.refreshToken.filter(rt => rt !== refreshToken);
  await foundUser.save();

  res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
  res.sendStatus(204);
}


module.exports = {
  login,
  register,
  refreshToken,
  logout
};