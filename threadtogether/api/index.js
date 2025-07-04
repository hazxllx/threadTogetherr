require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const uploadMiddleware = multer({ dest: 'uploads/' });
const app = express();

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET;

// === Middleware ===
app.use(cors({ credentials: true, origin: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, '/uploads')));

// === MongoDB Connection ===
mongoose.connect(process.env.MONGODB_URI);

// === Routes ===
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    res.status(400).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) return res.status(400).json('User not found');

  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) return res.status(500).json('Token signing failed');
      res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'lax',
      }).json({
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json('No token provided');

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token');
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path: filePath } = req.file;
  const ext = originalname.split('.').pop();
  const newPath = filePath + '.' + ext;
  fs.renameSync(filePath, newPath);

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Unauthorized');

    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });

    res.json(postDoc);
  });
});

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path: filePath } = req.file;
    const ext = originalname.split('.').pop();
    newPath = filePath + '.' + ext;
    fs.renameSync(filePath, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Unauthorized');

    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);
    if (String(postDoc.author) !== String(info.id)) {
      return res.status(400).json('You are not the author');
    }

    postDoc.title = title;
    postDoc.summary = summary;
    postDoc.content = content;
    if (newPath) postDoc.cover = newPath;

    await postDoc.save();
    res.json(postDoc);
  });
});

app.get('/post', async (req, res) => {
  const posts = await Post.find()
    .populate('author', ['username'])
    .sort({ createdAt: -1 })
    .limit(20);
  res.json(posts);
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  res.json(postDoc);
});

app.delete('/post/:id', async (req, res) => {
  const { token } = req.cookies;
  const { id } = req.params;

  if (!token) return res.status(403).json('Unauthorized');

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token');

    const postDoc = await Post.findById(id);
    if (!postDoc) return res.status(404).json('Post not found');

    if (String(postDoc.author) !== String(info.id)) {
      return res.status(403).json('You are not the author of this post');
    }

    if (postDoc.cover && fs.existsSync(postDoc.cover)) {
      fs.unlink(postDoc.cover, (err) => {
        if (err) console.error(err);
      });
    }

    await User.updateMany(
      { bookmarks: postDoc._id },
      { $pull: { bookmarks: postDoc._id } }
    );

    await postDoc.deleteOne();
    res.json('Post deleted successfully');
  });
});

app.post('/bookmark/:id', async (req, res) => {
  const { token } = req.cookies;
  const { id } = req.params;

  if (!token) return res.status(403).json('Unauthorized');

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token');

    const postDoc = await Post.findById(id);
    if (!postDoc) return res.status(404).json('Post not found');

    const userDoc = await User.findById(info.id);
    if (!userDoc) return res.status(404).json('User not found');

    const bookmarkIndex = userDoc.bookmarks.indexOf(id);

    if (bookmarkIndex === -1) {
      userDoc.bookmarks.push(id);
    } else {
      userDoc.bookmarks.splice(bookmarkIndex, 1);
    }

    await userDoc.save();
    res.json({ bookmarks: userDoc.bookmarks });
  });
});

app.get('/bookmarked-posts', async (req, res) => {
  const { token } = req.cookies;

  if (!token) return res.status(403).json('Unauthorized');

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json('Invalid or expired token');

    const userDoc = await User.findById(info.id).populate({
      path: 'bookmarks',
      populate: { path: 'author', select: 'username' },
    });

    res.json(userDoc.bookmarks);
  });
});

// === Serve React frontend ===
app.use(express.static(path.join(__dirname, '../client/build')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build/index.html'));
});

// === Start Server ===
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
