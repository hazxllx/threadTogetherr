// Import necessary modules from mongoose
const mongoose = require('mongoose'); 
const { Schema, model } = mongoose; // Destructure Schema and model to define models

// Define the PostSchema for creating Post documents in MongoDB
const PostSchema = new Schema({
  // 'title' field stores the title of the post as a string
  title: {
    type: String, // Field type is a string
    required: true, // Title is required for each post
  },

  // 'summary' field stores a short summary of the post as a string
  summary: {
    type: String, // Field type is a string
    required: true, // Summary is required for each post
  },

  // 'content' field stores the main content of the post as a string
  content: {
    type: String, // Field type is a string
    required: true, // Content is required for each post
  },

  // 'cover' field stores the file path or URL to the cover image of the post as a string
  cover: {
    type: String, // Field type is a string
    required: true, // Cover image URL or file path is required
  },

  // 'author' field references the 'User' model, indicating the user who created the post
  // This creates a relationship between posts and users
  author: {
    type: Schema.Types.ObjectId, // Field type is ObjectId, referencing another document
    ref: 'User', // Reference to the 'User' model (establishes a relationship between Post and User)
    required: true, // The author field is required
  },
}, {
  // The 'timestamps' option automatically adds 'createdAt' and 'updatedAt' fields to the post
  timestamps: true, // Automatically add creation and update timestamps
});

// Create the Post model based on the PostSchema
const PostModel = model('Post', PostSchema); // 'Post' is the name of the collection

// Export the PostModel so it can be used in other parts of the application
module.exports = PostModel;
