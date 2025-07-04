// Import necessary styles and components
import './App.css';
import { useEffect, useState } from 'react'; // React hooks for state and effect
import { Route, Routes } from "react-router-dom"; // For routing and navigation
import Layout from "./Layout"; // Main layout component
import IndexPage from "./pages/IndexPage"; // Home page component
import LoginPage from "./pages/LoginPage"; // Login page component
import RegisterPage from "./pages/RegisterPage"; // Registration page component
import CreatePost from "./pages/CreatePost"; // Page to create a post
import PostPage from "./pages/PostPage"; // Single post page
import EditPost from "./pages/EditPost"; // Edit post page
import Bookmark from "./pages/Bookmarks"; // Bookmarks page
import { UserContextProvider } from "./UserContext"; // Context provider for user data

function App() {
  // State to track if the app is still loading
  const [loading, setLoading] = useState(true);

  // Effect to simulate a loading state (e.g., waiting for data or assets)
  useEffect(() => {
    // Set a timeout to simulate loading for 2 seconds
    const timer = setTimeout(() => {
      setLoading(false); // After 2 seconds, set loading to false
    }, 2000);

    // Cleanup the timeout when the component unmounts
    return () => clearTimeout(timer);
  }, []); // Empty dependency array to run this effect only once on mount

  // If loading, display a splash screen
  if (loading) {
    return (
      <div className="splash-screen">
        <h1>Welcome to ThreadTogether</h1> {/* Welcome message */}
        <p>Loading...</p> {/* Loading text */}
      </div>
    );
  }

  // If not loading, render the main app with routes
  return (
    <UserContextProvider> {/* Provide user context to the app */}
      <Routes> {/* Define the routes of the application */}
        <Route path="/" element={<Layout />}> {/* Main layout route */}
          <Route index element={<IndexPage />} /> {/* Default route (home page) */}
          <Route path="/login" element={<LoginPage />} /> {/* Login page route */}
          <Route path="/register" element={<RegisterPage />} /> {/* Registration page route */}
          <Route path="/create" element={<CreatePost />} /> {/* Create post page route */}
          <Route path="/post/:id" element={<PostPage />} /> {/* Single post page route with dynamic ID */}
          <Route path="/edit/:id" element={<EditPost />} /> {/* Edit post page route with dynamic ID */}
          <Route path="/bookmarks" element={<Bookmark />} /> {/* Bookmarks page route */}
        </Route>
      </Routes>
    </UserContextProvider>
  );
}

export default App;
