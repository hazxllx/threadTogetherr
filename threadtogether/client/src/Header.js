import { Link } from "react-router-dom"; // Import Link component for navigation
import { useContext, useEffect } from "react"; // React hooks for context and side effects
import { UserContext } from "./UserContext"; // Import UserContext to manage user information

export default function Header() {
  // Access user information from the context
  const { setUserInfo, userInfo } = useContext(UserContext);

  // Effect to fetch user profile info when the component mounts
  useEffect(() => {
    // Fetch user profile data from the backend API
    fetch('http://localhost:4000/profile', {
      credentials: 'include', // Include cookies with the request for authentication
    })
      .then(response => response.json()) // Parse the JSON response
      .then(data => {
        // Set user information in context if the request is successful
        setUserInfo(data);
      })
      .catch(error => console.error('Error fetching user info:', error)); // Log error if fetching fails
  }, [setUserInfo]); // Effect runs only when setUserInfo changes (typically on mount)

  // Function to handle user logout
  function logout() {
    // Send a logout request to the backend
    fetch('http://localhost:4000/logout', {
      credentials: 'include', // Include cookies for authentication
      method: 'POST', // POST request to logout
    })
      .then(() => setUserInfo(null)) // Clear user info in context on successful logout
      .catch(error => console.error('Error logging out:', error)); // Log error if logout fails
  }

  // Extract the username from the userInfo object (if available)
  const username = userInfo?.username;

  return (
    <header>
      {/* Logo link to the homepage */}
      <Link to="/" className="logo">ThreadTogether</Link>
      <nav>
        {/* If the user is logged in, show the navigation links for creating posts and bookmarks */}
        {username ? (
          <>
            <Link to="/create">Create</Link> {/* Link to the Create Post page */}
            <Link to="/bookmarks">Bookmarks</Link> {/* Link to the Bookmarks page */}
            {/* Logout as Text, when clicked it triggers the logout function */}
            <span onClick={logout} className="logout">
              Logout ({username}) {/* Display username in the logout link */}
            </span>
          </>
        ) : (
          // If the user is not logged in, show Login and Register links
          <>
            <Link to="/login">Login</Link> {/* Link to the Login page */}
            <Link to="/register">Register</Link> {/* Link to the Register page */}
          </>
        )}
      </nav>
    </header>
  );
}
