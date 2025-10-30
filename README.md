# fullstack10.3
/**
 * ALL-IN-ONE Social Media App (Single File)
 *
 * Features:
 * - Express backend + MongoDB (Mongoose)
 * - JWT authentication (register/login)
 * - Users with profiles, follow/unfollow
 * - Posts with text, optional image upload (stored locally in ./public/uploads)
 * - Likes and comments
 * - Simple frontend served at "/" (vanilla JS) to demonstrate usage
 *
 * Usage:
 * 1) Install dependencies:
 *    npm init -y
 *    npm install express mongoose bcryptjs jsonwebtoken multer cors dotenv
 *
 * 2) Ensure MongoDB is running locally (mongodb://127.0.0.1:27017)
 *    or set env MONGODB_URI
 *
 * 3) Run:
 *    node app.js
 *
 * 4) Open http://localhost:5000 in browser
 *
 * Notes:
 * - This single-file demo is for learning and local testing only.
 * - In production, split code into modules, use S3 for uploads, secure secrets, add validation/rate limits.
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------------- Configuration -----------------
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/social_onefile';
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET';
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');

// ensure upload dir exists
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ----------------- Multer (file upload) -----------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    const name = `${Date.now()}_${Math.random().toString(36).slice(2,8)}${ext}`;
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB

// ----------------- Mongoose Models -----------------
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('MongoDB connect error', err); process.exit(1); });

const { Schema } = mongoose;

const UserSchema = new Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  bio: String,
  avatarUrl: String,
  followers: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

UserSchema.methods.safe = function() {
  const u = this.toObject();
  delete u.passwordHash;
  return u;
};

const User = mongoose.model('User', UserSchema);

const CommentSchema = new Schema({
  author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true }
}, { timestamps: true });

const PostSchema = new Schema({
  author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  imageUrl: String,
  likes: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  comments: [CommentSchema]
}, { timestamps: true });

const Post = mongoose.model('Post', PostSchema);

// ----------------- Auth Middleware -----------------
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Malformed Authorization header' });
  const token = parts[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = payload; // { id, username, iat, exp }
    next();
  });
}

// ----------------- Helper Functions -----------------
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}
async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}
function generateToken(user) {
  return jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}
function publicUrlForFilename(fname) {
  return `/uploads/${fname}`;
}

// ----------------- API Routes -----------------

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, bio } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'username, email, password required' });

    const existing = await User.findOne({ $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }] });
    if (existing) return res.status(409).json({ error: 'username or email already taken' });

    const passwordHash = await hashPassword(password);
    const user = new User({ username: username.toLowerCase(), email: email.toLowerCase(), passwordHash, bio });
    await user.save();
    const token = generateToken(user);
    res.status(201).json({ user: user.safe(), token });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;
    if (!emailOrUsername || !password) return res.status(400).json({ error: 'emailOrUsername and password required' });

    const user = await User.findOne({
      $or: [{ email: emailOrUsername.toLowerCase() }, { username: emailOrUsername.toLowerCase() }]
    });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await comparePassword(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ user: user.safe(), token });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upload avatar or post image (multipart/form-data, field 'file')
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const publicUrl = publicUrlForFilename(req.file.filename);
    res.json({ url: publicUrl });
  } catch (err) {
    console.error('Upload error', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get profile by username
app.get('/api/users/:username', async (req, res) => {
  try {
    const username = req.params.username.toLowerCase();
    const user = await User.findOne({ username }).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    // counts
    const postsCount = await Post.countDocuments({ author: user._id });
    res.json({ ...user, postsCount });
  } catch (err) {
    console.error('Get profile error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Follow/unfollow
app.post('/api/users/:username/follow', authMiddleware, async (req, res) => {
  try {
    const me = await User.findById(req.user.id);
    const target = await User.findOne({ username: req.params.username.toLowerCase() });
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target._id.equals(me._id)) return res.status(400).json({ error: 'Cannot follow yourself' });

    const isFollowing = me.following.some(f => f.equals(target._id));
    if (isFollowing) {
      me.following.pull(target._id);
      target.followers.pull(me._id);
      await me.save(); await target.save();
      return res.json({ message: 'Unfollowed' });
    } else {
      me.following.push(target._id);
      target.followers.push(me._id);
      await me.save(); await target.save();
      return res.json({ message: 'Followed' });
    }
  } catch (err) {
    console.error('Follow error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create post (body: { text, imageUrl? })
app.post('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { text, imageUrl } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text required' });
    const post = new Post({ author: req.user.id, text: text.trim(), imageUrl });
    await post.save();
    const populated = await Post.findById(post._id).populate('author', 'username avatarUrl');
    res.status(201).json(populated);
  } catch (err) {
    console.error('Create post error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get feed (paginated)
app.get('/api/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, parseInt(req.query.limit || '10'));
    const skip = (page - 1) * limit;
    const posts = await Post.find().sort({ createdAt: -1 }).skip(skip).limit(limit)
      .populate('author', 'username avatarUrl')
      .lean();
    // attach likeCount, commentCount
    posts.forEach(p => {
      p.likeCount = (p.likes || []).length;
      p.commentCount = (p.comments || []).length;
    });
    res.json(posts);
  } catch (err) {
    console.error('Get posts error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate('author', 'username avatarUrl').lean();
    if (!post) return res.status(404).json({ error: 'Post not found' });
    post.likeCount = (post.likes || []).length;
    post.commentCount = (post.comments || []).length;
    // populate comment authors
    const comments = await Promise.all((post.comments || []).map(async c => {
      const user = await User.findById(c.author).select('username avatarUrl').lean();
      return { _id: c._id, author: user, text: c.text, createdAt: c.createdAt };
    }));
    res.json({ ...post, comments });
  } catch (err) {
    console.error('Get post error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Like/unlike post
app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const liked = post.likes.some(u => u.equals(req.user.id));
    if (liked) {
      post.likes.pull(req.user.id);
      await post.save();
      return res.json({ liked: false, likeCount: post.likes.length });
    } else {
      post.likes.push(req.user.id);
      await post.save();
      return res.json({ liked: true, likeCount: post.likes.length });
    }
  } catch (err) {
    console.error('Like error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Comment on post
app.post('/api/posts/:id/comment', authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text required' });
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const comment = { author: req.user.id, text: text.trim() };
    post.comments.push(comment);
    await post.save();
    const lastComment = post.comments[post.comments.length - 1];
    const user = await User.findById(lastComment.author).select('username avatarUrl').lean();
    res.status(201).json({ _id: lastComment._id, author: user, text: lastComment.text, createdAt: lastComment.createdAt });
  } catch (err) {
    console.error('Comment error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete comment (only comment author or post author)
app.delete('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const post = await Post.findById(postId);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const comment = post.comments.id(commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.author.toString() !== req.user.id && post.author.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    comment.remove();
    await post.save();
    res.json({ message: 'Comment deleted' });
  } catch (err) {
    console.error('Delete comment error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete post (only author)
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (post.author.toString() !== req.user.id) return res.status(403).json({ error: 'Not authorized' });
    await post.remove();
    res.json({ message: 'Post deleted' });
  } catch (err) {
    console.error('Delete post error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------- Serve static frontend files -----------------
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.get('/', (req, res) => {
  res.type('html').send(frontendHtml);
});

// ----------------- Simple health route -----------------
app.get('/health', (req, res) => res.json({ ok: true }));

// ----------------- Start server -----------------
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

// ----------------- Minimal Frontend (single page) -----------------
const frontendHtml = `
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Mini Social (Single File)</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  body { font-family: system-ui, Arial; max-width:900px; margin:20px auto; padding:10px; color:#111 }
  header { display:flex; align-items:center; gap:10px; margin-bottom:16px }
  .card { border:1px solid #ddd; padding:12px; border-radius:8px; margin-bottom:12px; background:#fff }
  input, textarea { width:100%; padding:8px; margin-top:6px; margin-bottom:8px; border:1px solid #ccc; border-radius:6px }
  button { padding:8px 12px; border-radius:6px; border:none; background:#007bff; color:#fff; cursor:pointer }
  .muted { color:#666; font-size:0.9em }
  .row { display:flex; gap:8px; }
  .small { font-size:0.9em }
  img.post-image { max-width:100%; height:auto; margin-top:8px; border-radius:6px }
  .author { font-weight:600 }
</style>
</head>
<body>
<header>
  <h2 style="margin:0">Mini Social</h2>
  <div style="margin-left:auto">
    <span id="who" class="muted"></span>
    <button id="logoutBtn" style="display:none; margin-left:8px; background:#e74c3c">Logout</button>
  </div>
</header>

<div id="auth" class="card">
  <div id="authForms">
    <h3>Register</h3>
    <input id="regUsername" placeholder="username (no spaces)" />
    <input id="regEmail" placeholder="email" />
    <input id="regPassword" placeholder="password" type="password" />
    <button id="registerBtn">Register</button>
    <hr />
    <h3>Login</h3>
    <input id="logEmailUser" placeholder="email or username" />
    <input id="logPassword" placeholder="password" type="password" />
    <button id="loginBtn">Login</button>
  </div>
</div>

<div id="createSection" class="card" style="display:none">
  <h3>Create Post</h3>
  <textarea id="postText" rows="3" placeholder="Share something..."></textarea>
  <input id="postFile" type="file" accept="image/*" />
  <div class="row" style="justify-content:flex-end">
    <button id="postBtn">Post</button>
  </div>
</div>

<div id="feed"></div>

<script>
const API_BASE = '/api';
const whoEl = document.getElementById('who');
const logoutBtn = document.getElementById('logoutBtn');

function setToken(token) {
  if (token) localStorage.setItem('token', token); else localStorage.removeItem('token');
}
function getToken() { return localStorage.getItem('token'); }

function authHeaders() {
  const t = getToken();
  return t ? { 'Authorization': 'Bearer ' + t } : {};
}

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  Object.assign(headers, { 'Content-Type': 'application/json' });
  Object.assign(headers, authHeaders());
  const res = await fetch(API_BASE + path, { ...opts, headers });
  const txt = await res.text();
  try { return { ok: res.ok, status: res.status, data: txt ? JSON.parse(txt) : null }; }
  catch (e) { return { ok: res.ok, status: res.status, data: txt }; }
}

async function apiForm(path, formData) {
  const headers = authHeaders();
  const res = await fetch(API_BASE + path, { method: 'POST', headers, body: formData });
  const txt = await res.text();
  try { return { ok: res.ok, status: res.status, data: txt ? JSON.parse(txt) : null }; }
  catch (e) { return { ok: res.ok, status: res.status, data: txt }; }
}

// UI actions
document.getElementById('registerBtn').addEventListener('click', async () => {
  const username = document.getElementById('regUsername').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const r = await api('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
  if (!r.ok) return alert(r.data?.error || 'Register failed');
  setToken(r.data.token);
  onLoggedIn(r.data.user);
});

document.getElementById('loginBtn').addEventListener('click', async () => {
  const emailOrUsername = document.getElementById('logEmailUser').value.trim();
  const password = document.getElementById('logPassword').value;
  const r = await api('/auth/login', { method: 'POST', body: JSON.stringify({ emailOrUsername, password }) });
  if (!r.ok) return alert(r.data?.error || 'Login failed');
  setToken(r.data.token);
  onLoggedIn(r.data.user);
});

logoutBtn.addEventListener('click', () => {
  setToken(null);
  onLoggedOut();
});

// create post
document.getElementById('postBtn').addEventListener('click', async () => {
  const text = document.getElementById('postText').value.trim();
  if (!text) return alert('Enter text');
  const fileInput = document.getElementById('postFile');
  let imageUrl = null;
  if (fileInput.files && fileInput.files[0]) {
    // upload
    const form = new FormData();
    form.append('file', fileInput.files[0]);
    const up = await apiForm('/upload', form);
    if (!up.ok) return alert(up.data?.error || 'Upload failed');
    imageUrl = up.data.url;
  }
  const r = await api('/posts', { method: 'POST', body: JSON.stringify({ text, imageUrl }) });
  if (!r.ok) return alert(r.data?.error || 'Post failed');
  document.getElementById('postText').value = '';
  fileInput.value = '';
  loadFeed();
});

async function onLoggedIn(user) {
  document.getElementById('authForms').style.display = 'none';
  document.getElementById('createSection').style.display = 'block';
  logoutBtn.style.display = 'inline-block';
  whoEl.textContent = user.username;
  loadFeed();
}

function onLoggedOut() {
  document.getElementById('authForms').style.display = 'block';
  document.getElementById('createSection').style.display = 'none';
  logoutBtn.style.display = 'none';
  whoEl.textContent = '';
  loadFeed();
}

async function tryRestore() {
  const t = getToken();
  if (!t) { onLoggedOut(); return; }
  // try to get profile to validate token
  const res = await api('/users/me', { method: 'GET' });
  if (res.ok) onLoggedIn(res.data);
  else { setToken(null); onLoggedOut(); }
}

// minimal endpoint to get current user (not implemented server-side yet?) We'll implement below
// But to keep simple, fetch user via token by calling /api/users/:username after login; server returns user for /users/me
// Implement /api/users/me on server side:
(async function ensureMeEndpoint() {
  // if missing, nothing to do - server provides /api/users/me implemented below
})();

// load feed
async function loadFeed() {
  const r = await api('/posts');
  const container = document.getElementById('feed');
  container.innerHTML = '';
  if (!r.ok) { container.innerHTML = '<div class="card">Could not load feed</div>'; return; }
  const posts = r.data;
  if (posts.length === 0) { container.innerHTML = '<div class="card">No posts yet</div>'; return; }
  posts.forEach(p => {
    const div = document.createElement('div');
    div.className = 'card';
    const d = new Date(p.createdAt);
    div.innerHTML = \`
      <div><span class="author">\${p.author?.username || 'Unknown'}</span> <span class="muted small">• \${d.toLocaleString()}</span></div>
      <div style="margin-top:8px">\${escapeHtml(p.text)}</div>
      \${p.imageUrl ? '<img src="'+ p.imageUrl +'" class="post-image" />' : ''}
      <div style="margin-top:8px" class="row">
        <button data-id="\${p._id}" class="likeBtn">\${p.likeCount || 0} 👍</button>
        <button data-id="\${p._id}" class="commentToggle">💬 \${p.commentCount || 0}</button>
      </div>
      <div class="comments" style="display:none; margin-top:10px"></div>
    \`;
    container.appendChild(div);
  });
  // attach handlers
  document.querySelectorAll('.likeBtn').forEach(b => b.addEventListener('click', async (e) => {
    const id = e.target.dataset.id;
    const res = await api('/posts/' + id + '/like', { method: 'POST' });
    if (!res.ok) return alert(res.data?.error || 'Like failed');
    loadFeed();
  }));
  document.querySelectorAll('.commentToggle').forEach(b => b.addEventListener('click', async (e) => {
    const id = e.target.dataset.id;
    const card = e.target.closest('.card');
    const commentsDiv = card.querySelector('.comments');
    if (commentsDiv.style.display === 'none') {
      // show and load comments
      const res = await api('/posts/' + id);
      if (!res.ok) return alert(res.data?.error || 'Load post failed');
      const post = res.data;
      commentsDiv.innerHTML = '<div style="font-weight:600">Comments</div>';
      const form = document.createElement('div');
      form.innerHTML = '<input placeholder=\"Comment...\" class=\"commentInput\" /><button class=\"sendComment\">Send</button>';
      commentsDiv.appendChild(form);
      const list = document.createElement('div');
      list.style.marginTop = '8px';
      (post.comments || []).forEach(c => {
        list.innerHTML += '<div style="border-top:1px solid #eee; padding-top:8px"><b>' + (c.author?.username||'user') + '</b><div>' + escapeHtml(c.text) + '</div></div>';
      });
      commentsDiv.appendChild(list);
      commentsDiv.style.display = 'block';
      form.querySelector('.sendComment').addEventListener('click', async () => {
        const text = form.querySelector('.commentInput').value;
        if (!text) return alert('Enter comment');
        const r2 = await api('/posts/' + id + '/comment', { method: 'POST', body: JSON.stringify({ text }) });
        if (!r2.ok) return alert(r2.data?.error || 'Comment failed');
        loadFeed();
      });
    } else {
      commentsDiv.style.display = 'none';
    }
  }));
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/[&<>"']/g, function(m) { return ({ '&': '&amp;', '<':'&lt;', '>':'&gt;', '\"':'&quot;', \"'\":'&#39;' })[m]; });
}

// On load
tryRestore();
loadFeed();
</script>
</body>
</html>
`;

// ----------------- Extra endpoint: get current user by token -----------------
app.get('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    console.error('users/me error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------- End of file -----------------
