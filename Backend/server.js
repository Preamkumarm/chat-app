// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  }
});

// MongoDB connection
mongoose.connect("mongodb+srv://preamkumarmano_db_user:chatApp123@cluster0.j3bamso.mongodb.net/chatapp", {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('MongoDB connected successfully!');
  console.log('Database: chatapp');
  console.log('Connection: MongoDB Atlas');
})

// User Schema
const userSchema = new mongoose.Schema({
  phoneNumber: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  profilePicture: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Group Schema
const groupSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: String,
  admin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  groupPicture: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: String,
  messageType: {
    type: String,
    enum: ['text', 'image', 'video', 'audio', 'location', 'document'],
    default: 'text'
  },
  fileUrl: String,
  fileName: String,
  fileSize: Number,
  location: {
    latitude: Number,
    longitude: Number,
    address: String
  },
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Group'
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  isPrivate: {
    type: Boolean,
    default: false
  },
  readBy: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    readAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Order Schema
const orderSchema = new mongoose.Schema({
  customer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  admin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    name: String,
    quantity: Number,
    price: Number
  }],
  totalAmount: Number,
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'preparing', 'ready', 'delivered', 'cancelled'],
    default: 'pending'
  },
  deliveryLocation: {
    latitude: Number,
    longitude: Number,
    address: String
  },
  notes: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Models
const User = mongoose.model('User', userSchema);
const Group = mongoose.model('Group', groupSchema);
const Message = mongoose.model('Message', messageSchema);
const Order = mongoose.model('Order', orderSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

// Socket middleware for authentication
const socketAuth = (socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
};

io.use(socketAuth);

// Routes

// User registration/login with phone number
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phoneNumber, name } = req.body;
    
    // Find or create user
    let user = await User.findOne({ phoneNumber });
    
    if (!user) {
      user = new User({
        phoneNumber,
        name
      });
      await user.save();
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, phoneNumber: user.phoneNumber },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        phoneNumber: user.phoneNumber,
        name: user.name,
        isAdmin: user.isAdmin,
        profilePicture: user.profilePicture
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin login with password (separate from regular users)
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { phoneNumber, name, adminPassword } = req.body;
    
    // Check admin password (you should use environment variable)
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
    
    if (adminPassword !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
    
    // Find or create admin user
    let admin = await User.findOne({ phoneNumber });
    
    if (!admin) {
      admin = new User({
        phoneNumber,
        name,
        isAdmin: true
      });
      await admin.save();
    } else if (!admin.isAdmin) {
      // Make existing user an admin
      admin.isAdmin = true;
      admin.name = name; // Update name if provided
      await admin.save();
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: admin._id, phoneNumber: admin.phoneNumber },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      token,
      user: {
        id: admin._id,
        phoneNumber: admin.phoneNumber,
        name: admin.name,
        isAdmin: admin.isAdmin,
        profilePicture: admin.profilePicture
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create admin user (one-time setup route)
app.post('/api/auth/admin/create', async (req, res) => {
  try {
    const { phoneNumber, name, adminSecretKey } = req.body;
    
    // Use a secret key for initial admin creation
    const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || 'super-secret-admin-key-2024';
    
    if (adminSecretKey !== ADMIN_SECRET) {
      return res.status(403).json({ error: 'Invalid admin secret key' });
    }
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ phoneNumber });
    if (existingAdmin) {
      if (existingAdmin.isAdmin) {
        return res.status(400).json({ error: 'Admin already exists with this phone number' });
      } else {
        // Make existing user an admin
        existingAdmin.isAdmin = true;
        await existingAdmin.save();
        return res.json({ 
          message: 'Existing user promoted to admin successfully', 
          admin: {
            id: existingAdmin._id,
            phoneNumber: existingAdmin.phoneNumber,
            name: existingAdmin.name,
            isAdmin: existingAdmin.isAdmin
          }
        });
      }
    }
    
    const admin = new User({
      phoneNumber,
      name,
      isAdmin: true
    });
    
    await admin.save();
    res.json({ 
      message: 'Admin created successfully', 
      admin: {
        id: admin._id,
        phoneNumber: admin.phoneNumber,
        name: admin.name,
        isAdmin: admin.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-__v');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
app.put("/api/user/profile", verifyToken, upload.single("profilePicture"), async (req, res) => {
  try {
    const updates = { name: req.body.name };
    if (req.file) {
      updates.profilePicture = req.file.path; // secure_url
      updates.profilePictureId = req.file.filename; // public_id
    }
    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin routes

// Create group (admin only)
app.post("/api/admin/groups", verifyToken, upload.single("groupPicture"), async (req, res) => {
  try {
    const admin = await User.findById(req.user.userId);
    if (!admin.isAdmin) return res.status(403).json({ error: "Admins only" });

    const { name, description, memberIds } = req.body;
    const group = new Group({
      name,
      description,
      admin: req.user.userId,
      members: memberIds ? JSON.parse(memberIds) : [],
      groupPicture: req.file ? req.file.path : null,
      groupPictureId: req.file ? req.file.filename : null
    });
    await group.save();
    await group.populate("admin members", "name phoneNumber profilePicture");
    res.json(group);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all groups (admin only)
app.get('/api/admin/groups', verifyToken, async (req, res) => {
  try {
    const admin = await User.findById(req.user.userId);
    if (!admin.isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const groups = await Group.find({ admin: req.user.userId })
      .populate('admin members', 'name phoneNumber profilePicture')
      .sort({ createdAt: -1 });
    
    res.json(groups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add members to group (admin only)
app.post('/api/admin/groups/:groupId/members', verifyToken, async (req, res) => {
  try {
    const admin = await User.findById(req.user.userId);
    if (!admin.isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const { memberIds } = req.body;
    const group = await Group.findById(req.params.groupId);
    
    if (group.admin.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'You can only manage your own groups' });
    }
    
    // Add new members
    const newMembers = memberIds.filter(id => !group.members.includes(id));
    group.members.push(...newMembers);
    await group.save();
    
    await group.populate('admin members', 'name phoneNumber profilePicture');
    
    // Notify new members via socket
    newMembers.forEach(memberId => {
      io.to(memberId).emit('addedToGroup', group);
    });
    
    res.json(group);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user groups
app.get('/api/groups', verifyToken, async (req, res) => {
  try {
    const groups = await Group.find({ 
      members: req.user.userId 
    })
    .populate('admin', 'name phoneNumber profilePicture')
    .sort({ createdAt: -1 });
    
    res.json(groups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send message to group (admin only) or private message
app.post("/api/messages", verifyToken, upload.single("file"), async (req, res) => {
  try {
    const { content, messageType, groupId, recipientId, isPrivate, location } = req.body;
    const messageData = {
      sender: req.user.userId,
      content,
      messageType: messageType || "text",
      isPrivate: isPrivate || false,
    };
    if (req.file) {
      messageData.fileUrl = req.file.path;
      messageData.fileName = req.file.originalname;
      messageData.fileSize = req.file.size;
      messageData.filePublicId = req.file.filename;
    }
    if (location) {
      messageData.location = JSON.parse(location);
      messageData.messageType = "location";
    }
    if (groupId) messageData.group = groupId;
    if (recipientId) { messageData.recipient = recipientId; messageData.isPrivate = true; }
    const message = new Message(messageData);
    await message.save();
    await message.populate("sender", "name phoneNumber profilePicture");
    res.json(message);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Get messages for a group or private chat
app.get('/api/messages', verifyToken, async (req, res) => {
  try {
    const { groupId, recipientId, page = 1, limit = 50 } = req.query;
    
    let query = {};
    
    if (groupId) {
      query.group = groupId;
      query.isPrivate = false;
    } else if (recipientId) {
      query.$or = [
        { sender: req.user.userId, recipient: recipientId },
        { sender: recipientId, recipient: req.user.userId }
      ];
      query.isPrivate = true;
    }
    
    const messages = await Message.find(query)
      .populate('sender', 'name phoneNumber profilePicture')
      .populate('recipient', 'name phoneNumber profilePicture')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    res.json(messages.reverse());
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create order
app.post('/api/orders', verifyToken, async (req, res) => {
  try {
    const { adminId, items, deliveryLocation, notes } = req.body;
    
    const totalAmount = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    const order = new Order({
      customer: req.user.userId,
      admin: adminId,
      items,
      totalAmount,
      deliveryLocation,
      notes
    });
    
    await order.save();
    await order.populate('customer admin', 'name phoneNumber');
    
    // Notify admin
    io.to(adminId).emit('newOrder', order);
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get orders
app.get('/api/orders', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    let query = {};
    
    if (user.isAdmin) {
      query.admin = req.user.userId;
    } else {
      query.customer = req.user.userId;
    }
    
    const orders = await Order.find(query)
      .populate('customer admin', 'name phoneNumber')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update order status (admin only)
app.put('/api/orders/:orderId/status', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user.isAdmin) {
      return res.status(403).json({ error: 'Only admin can update order status' });
    }
    
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.orderId,
      { status },
      { new: true }
    ).populate('customer admin', 'name phoneNumber');
    
    // Notify customer
    io.to(order.customer._id.toString()).emit('orderStatusUpdated', order);
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users (for admin to add to groups)
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.userId } })
      .select('name phoneNumber profilePicture isOnline lastSeen')
      .sort({ name: 1 });
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete message and associated Cloudinary file (admin or sender only)
app.delete("/api/messages/:messageId", verifyToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) return res.status(404).json({ error: "Message not found" });
    const user = await User.findById(req.user.userId);
    if (message.sender.toString() !== req.user.userId && !user.isAdmin) {
      return res.status(403).json({ error: "Not authorized" });
    }
    if (message.filePublicId) {
      let type = "raw";
      if (message.messageType === "image") type = "image";
      if (["video", "audio"].includes(message.messageType)) type = "video";
      await deleteFromCloudinary(message.filePublicId, type);
    }
    await Message.findByIdAndDelete(req.params.messageId);
    res.json({ message: "Message deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Get file info from Cloudinary (for optimization)
app.get('/api/file-info/:publicId', verifyToken, async (req, res) => {
  try {
    const { publicId } = req.params;
    const { resource_type = 'image' } = req.query;
    
    const result = await cloudinary.api.resource(publicId, {
      resource_type: resource_type
    });
    
    res.json({
      url: result.secure_url,
      size: result.bytes,
      format: result.format,
      width: result.width,
      height: result.height,
      created_at: result.created_at
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TEMPORARY ROUTE - Make user admin (remove after use)
app.post('/api/make-admin', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
    
    const user = await User.findOneAndUpdate(
      { phoneNumber: phoneNumber },
      { isAdmin: true },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ 
      message: 'User promoted to admin successfully', 
      user: {
        id: user._id,
        phoneNumber: user.phoneNumber,
        name: user.name,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO connection handling
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.userId);
  
  // Store socket for user
  userSockets.set(socket.userId, socket.id);
  
  // Update user online status
  User.findByIdAndUpdate(socket.userId, { 
    isOnline: true 
  }).exec();
  
  // Join user to their own room
  socket.join(socket.userId);
  
  // Handle joining group rooms
  socket.on('joinGroup', (groupId) => {
    socket.join(groupId);
  });
  
  // Handle leaving group rooms
  socket.on('leaveGroup', (groupId) => {
    socket.leave(groupId);
  });
  
  // Handle typing indicators
  socket.on('typing', ({ groupId, recipientId, isTyping }) => {
    if (groupId) {
      socket.to(groupId).emit('userTyping', {
        userId: socket.userId,
        isTyping
      });
    } else if (recipientId) {
      socket.to(recipientId).emit('userTyping', {
        userId: socket.userId,
        isTyping
      });
    }
  });
  
  // Handle message read status
  socket.on('markAsRead', async ({ messageId }) => {
    try {
      await Message.findByIdAndUpdate(messageId, {
        $addToSet: {
          readBy: {
            user: socket.userId,
            readAt: new Date()
          }
        }
      });
    } catch (error) {
      console.error('Error marking message as read:', error);
    }
  });
  
  // Handle location sharing
  socket.on('shareLocation', ({ recipientId, location }) => {
    socket.to(recipientId).emit('locationReceived', {
      senderId: socket.userId,
      location
    });
  });
  
  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.userId);
    
    // Remove socket from map
    userSockets.delete(socket.userId);
    
    // Update user offline status
    User.findByIdAndUpdate(socket.userId, {
      isOnline: false,
      lastSeen: new Date()
    }).exec();
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;