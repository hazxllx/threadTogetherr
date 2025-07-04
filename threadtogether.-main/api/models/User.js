// Import necessary modules from mongoose
const mongoose = require('mongoose'); 
const { Schema, model } = mongoose; // Destructure Schema and model to define models

// Define the UserSchema for creating User documents in MongoDB
const UserSchema = new Schema({
  // 'username' field is a string, required, must have at least 4 characters, and must be unique
  username: {
    type: String, // Field type is a string
    required: true, // This field is required (cannot be empty)
    min: 4, // Minimum length of username is 4 characters
    unique: true, // Username must be unique (cannot have duplicate values)
  },
  
  // 'password' field is a string, required to store the user's password
  password: {
    type: String, // Field type is a string
    required: true, // This field is required (cannot be empty)
  },

  // 'bookmarks' field is an array that will store ObjectIds referencing the 'Post' collection
  // This allows users to have a list of bookmarked posts
  bookmarks: [{
    type: mongoose.Schema.Types.ObjectId, // Type is ObjectId which refers to another document
    ref: 'Post', // Reference to the 'Post' model, establishing a relationship with the 'Post' collection
    default: [], // Default value is an empty array if no bookmarks are assigned
  }],
});

// Create the User model based on the UserSchema
const UserModel = model('User', UserSchema); // 'User' is the name of the collection

// Export the UserModel so it can be used in other parts of the application
module.exports = UserModel;
