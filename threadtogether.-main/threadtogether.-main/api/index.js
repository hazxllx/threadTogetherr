// Import necessary libraries
const express = require('express'); // Web framework for routing
const cors = require('cors'); // Middleware for enabling Cross-Origin Resource Sharing
const mongoose = require('mongoose'); // MongoDB object modeling for Node.js
const User = require('./models/User'); // User model for interacting with user data in MongoDB
const Post = require('./models/Post'); // Post model for interacting with posts in MongoDB
const bcrypt = require('bcryptjs'); // Library for hashing passwords
const jwt = require('jsonwebtoken'); // Library for creating and verifying JWT tokens
const cookieParser = require('cookie-parser'); // Middleware for parsing cookies
const multer = require('multer'); // Middleware for handling file uploads
const fs = require('fs'); // File system module to interact with the file system

// Set up file upload destination using multer
const uploadMiddleware = multer({ dest: 'uploads/' }); // Store uploaded files in the 'uploads' folder

const app = express(); // Initialize Express application

// Salt for password hashing, used for bcrypt
const salt = bcrypt.genSaltSync(10); // Generate salt for bcrypt hashing

// Secret for JWT signing (JSON Web Token)
const secret = 'asdfe45we45w345wegw345werjktjwertkj'; // A secret key for JWT signing

// Middlewares
app.use(cors({ credentials: true, origin: 'http://localhost:3000' })); // Enable CORS with specific frontend origin
app.use(express.json()); // Parse incoming JSON requests
app.use(cookieParser()); // Parse cookies sent with the request
app.use('/uploads', express.static(__dirname + '/uploads')); // Serve static files from the 'uploads' folder

// MongoDB connection
mongoose.connect('mongodb+srv://hazel:holyshit@cluster0.vhnu0bv.mongodb.net/fp?retryWrites=true&w=majority'); // Connect to MongoDB database

// Register route to create a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body; // Extract username and password from the request body
  try {
    // Create a new user document with hashed password
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt), // Hash the password before storing it
    });
    res.json(userDoc); // Send the created user document as a response
  } catch (e) {
    res.status(400).json(e); // Send error response if creation fails
  }
});

// Login route to authenticate a user
app.post('/login', async (req, res) => {
  const { username, password } = req.body; // Extract username and password from the request body
  const userDoc = await User.findOne({ username }); // Find user by username in the database
  if (!userDoc) return res.status(400).json('User not found'); // Return error if user not found

  // Compare the provided password with the stored hash
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    // Sign JWT token if password is correct
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) return res.status(500).json('Token signing failed'); // Return error if token signing fails
      res.cookie('token', token).json({ // Set token in the cookies and return user data
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json('Wrong credentials'); // Return error if password is incorrect
  }
});

// Profile route to get logged-in user's profile
app.get('/profile', (req, res) => {
  const { token } = req.cookies; // Get the JWT token from cookies
  if (!token) return res.status(401).json('No token provided'); // Return error if no token is provided

  // Verify the JWT token
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token'); // Return error if token is invalid or expired
    res.json(info); // Return decoded token info (user data)
  });
});

// Logout route to clear the token and log out the user
app.post('/logout', (req, res) => {
  res.cookie('token', '').json('ok'); // Clear the token cookie when logging out
});

// Post creation route with file upload functionality
app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path } = req.file; // Get file details from the upload
  const ext = originalname.split('.').pop(); // Get the file extension
  const newPath = path + '.' + ext; // Create a new file path with the correct extension
  fs.renameSync(path, newPath); // Rename the file to include the extension

  const { token } = req.cookies; // Get token from cookies
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Unauthorized'); // Return error if token is invalid

    const { title, summary, content } = req.body; // Extract post data from request body
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath, // Set the file path as the cover image
      author: info.id, // Set the author as the logged-in user
    });

    res.json(postDoc); // Send the created post document as a response
  });
});

// Post update route with file upload functionality
app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file; // Get file details from the upload
    const ext = originalname.split('.').pop(); // Get the file extension
    newPath = path + '.' + ext; // Create a new file path with the extension
    fs.renameSync(path, newPath); // Rename the file to include the extension
  }

  const { token } = req.cookies; // Get token from cookies
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Unauthorized'); // Return error if token is invalid

    const { id, title, summary, content } = req.body; // Extract post update data
    const postDoc = await Post.findById(id); // Find the post by ID

    if (String(postDoc.author) !== String(info.id)) {
      return res.status(400).json('You are not the author'); // Return error if the user is not the author
    }

    postDoc.title = title; // Update the post title
    postDoc.summary = summary; // Update the post summary
    postDoc.content = content; // Update the post content
    if (newPath) postDoc.cover = newPath; // Update the cover image if a new file was uploaded

    await postDoc.save(); // Save the updated post
    res.json(postDoc); // Send the updated post as a response
  });
});

// Get all posts route
app.get('/post', async (req, res) => {
  const posts = await Post.find() // Get all posts from the database
    .populate('author', ['username']) // Populate author details
    .sort({ createdAt: -1 }) // Sort posts by creation date, descending
    .limit(20); // Limit to the latest 20 posts
  res.json(posts); // Return the posts as a response
});

// Get a single post by ID route
app.get('/post/:id', async (req, res) => {
  const { id } = req.params; // Get post ID from URL parameters
  const postDoc = await Post.findById(id).populate('author', ['username']); // Find the post and populate author details
  res.json(postDoc); // Return the post as a response
});

// Delete a post by ID route
app.delete('/post/:id', async (req, res) => {
  const { token } = req.cookies; // Get token from cookies
  const { id } = req.params; // Get post ID from URL parameters

  if (!token) return res.status(403).json('Unauthorized'); // Return error if no token

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token'); // Return error if token is invalid

    const postDoc = await Post.findById(id); // Find the post by ID
    if (!postDoc) return res.status(404).json('Post not found'); // Return error if post not found

    if (String(postDoc.author) !== String(info.id)) {
      return res.status(403).json('You are not the author of this post'); // Return error if the user is not the author
    }

    if (postDoc.cover && fs.existsSync(postDoc.cover)) { // Delete the cover image if it exists
      fs.unlink(postDoc.cover, (err) => {
        if (err) console.error(err);
      });
    }

    // Remove this post from any user's bookmarks
    await User.updateMany(
      { bookmarks: postDoc._id },
      { $pull: { bookmarks: postDoc._id } }
    );

    await postDoc.deleteOne(); // Delete the post from the database
    res.json('Post deleted successfully'); // Return success message
  });
});

// Add or remove a post from the user's bookmarks
app.post('/bookmark/:id', async (req, res) => {
  const { token } = req.cookies; // Get token from cookies
  const { id } = req.params; // Get post ID from URL parameters

  if (!token) return res.status(403).json('Unauthorized'); // Return error if no token

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token'); // Return error if token is invalid

    const postDoc = await Post.findById(id); // Find the post by ID
    if (!postDoc) return res.status(404).json('Post not found'); // Return error if post not found

    const userDoc = await User.findById(info.id); // Find the user by ID
    if (!userDoc) return res.status(404).json('User not found'); // Return error if user not found

    const bookmarkIndex = userDoc.bookmarks.indexOf(id); // Check if post is already bookmarked

    if (bookmarkIndex === -1) {
      userDoc.bookmarks.push(id); // Add post to bookmarks if not already present
    } else {
      userDoc.bookmarks.splice(bookmarkIndex, 1); // Remove post from bookmarks if already present
    }

    await userDoc.save(); // Save the updated user document
    res.json({ bookmarks: userDoc.bookmarks }); // Return updated bookmarks
  });
});

// Get all bookmarked posts for the logged-in user
app.get('/bookmarked-posts', async (req, res) => {
  const { token } = req.cookies; // Get token from cookies

  if (!token) return res.status(403).json('Unauthorized'); // Return error if no token

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token'); // Return error if token is invalid

    const userDoc = await User.findById(info.id).populate({ // Find the user and populate their bookmarks
      path: 'bookmarks',
      populate: { path: 'author', select: 'username' }, // Populate author details for each bookmark
    });

    res.json(userDoc.bookmarks); // Return the user's bookmarks as a response
  });
});

// Start the server on port 4000
app.listen(4000, () => {
  console.log('Server running on http://localhost:4000');
});
