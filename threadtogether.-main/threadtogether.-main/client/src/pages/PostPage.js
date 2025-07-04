import { useContext, useEffect, useState } from "react"; 
// Import necessary React hooks: `useState` for managing state, `useEffect` for side effects like fetching data, and `useContext` to access user context.
import { useParams, useNavigate, Link } from "react-router-dom"; 
// Import `useParams` to access URL parameters (e.g., `id` of the post), `useNavigate` for navigation, and `Link` for creating navigational links to other pages.
import { formatISO9075 } from "date-fns"; 
// Import `formatISO9075` from `date-fns` to format the post's creation date into a human-readable format.
import { UserContext } from "../UserContext"; 
// Import `UserContext` to get and set the user data (such as authentication and bookmarks).

export default function PostPage() { 
  // Define the `PostPage` component for displaying individual post details.

  const [postInfo, setPostInfo] = useState(null); 
  // `postInfo` state stores the post's information fetched from the backend.
  
  const [bookmarked, setBookmarked] = useState(false); 
  // `bookmarked` state tracks whether the current post is bookmarked by the user.
  
  const [loading, setLoading] = useState(true); 
  // `loading` state tracks whether the post data is still being loaded from the server.
  
  const [error, setError] = useState(null); 
  // `error` state holds any error messages that occur during data fetching.

  const { userInfo, setUserInfo } = useContext(UserContext); 
  // Get `userInfo` and `setUserInfo` from `UserContext`. `userInfo` holds user data, and `setUserInfo` updates the user context.
  
  const { id } = useParams(); 
  // Get the `id` of the post from the URL parameters (e.g., `/post/:id`).

  const navigate = useNavigate(); 
  // `navigate` allows programmatic navigation to different routes (e.g., after post deletion).

  useEffect(() => { 
    // `useEffect` runs when the component mounts or when `id` or `userInfo` changes.
    
    setLoading(true); 
    // Set `loading` to `true` before fetching data.

    fetch(`http://localhost:4000/post/${id}`, {
      credentials: "include", 
      // Send the `id` in the request to fetch the post data. `credentials: "include"` includes authentication cookies.
    })
      .then((res) => {
        if (!res.ok) { 
          throw new Error("Failed to fetch post"); 
          // If the response isn't ok, throw an error.
        }
        return res.json(); 
        // Parse the response as JSON.
      })
      .then((data) => {
        setPostInfo(data); 
        // Set `postInfo` state with the fetched post data.
        
        setError(null); 
        // Reset any previous errors.
        
        if (userInfo?.bookmarks?.includes(data._id)) { 
          // If the post's ID is in the user's bookmarks, mark it as bookmarked.
          setBookmarked(true);
        }

        setLoading(false); 
        // Set `loading` to `false` after the post data has been successfully fetched.
      })
      .catch((err) => {
        console.error("Error fetching post:", err);
        setError("Error loading post"); 
        // If an error occurs during fetch, set the `error` state to display an error message.
        setLoading(false); 
        // Set `loading` to `false` even when there's an error.
      });
  }, [id, userInfo]); 
  // The effect runs when `id` or `userInfo` changes.

  if (loading) return <div>Loading...</div>; 
  // If the post is still being loaded, display a loading message.

  if (error) return <div>{error}</div>; 
  // If there was an error loading the post, display the error message.

  if (!postInfo || !postInfo.author) return <div>Post not found.</div>; 
  // If `postInfo` or `postInfo.author` is missing (i.e., post data not found), display a "Post not found" message.

  const isAuthor = userInfo?.id === postInfo.author._id; 
  // Check if the logged-in user is the author of the post.

  const handleDelete = () => { 
    // Function to handle post deletion.
    
    fetch(`http://localhost:4000/post/${id}`, {
      method: "DELETE", 
      // Send a `DELETE` request to the server to delete the post.
      credentials: "include", 
      // Include credentials (cookies) to authenticate the user.
    })
      .then((res) => {
        if (res.ok) { 
          alert("Post deleted successfully");
          navigate("/"); 
          // If deletion is successful, show an alert and redirect the user to the homepage.
        } else {
          alert("Failed to delete post"); 
          // If deletion fails, show an error message.
        }
      })
      .catch((err) => console.error("Error deleting post:", err)); 
      // Log any errors that occur during the deletion process.
  };

  const handleBookmark = () => { 
    // Function to handle bookmarking a post.

    fetch(`http://localhost:4000/bookmark/${postInfo._id}`, {
      method: "POST", 
      // Send a `POST` request to the server to bookmark the post.
      credentials: "include", 
      // Include credentials (cookies) to authenticate the user.
    })
      .then((res) => res.json()) 
      // Parse the response as JSON, which will contain the updated list of bookmarks.
      .then((data) => {
        setBookmarked((prev) => !prev); 
        // Toggle the `bookmarked` state (add or remove the bookmark).
        
        setUserInfo((prevInfo) => { 
          return {
            ...prevInfo, 
            bookmarks: data.bookmarks, 
            // Update the user's bookmarks in the context.
          };
        });
      })
      .catch(() => alert("Bookmark action failed"));
      // If the request fails, show an alert indicating the failure.
  };

  return (
    <div className="post-page">
      {/* Container for the entire post page */}
      
      <div className="post-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        {/* Header section with title and buttons (bookmark and delete) */}
        <h1 style={{ textAlign: "center", flex: 1 }}>{postInfo.title}</h1>
        {/* Display the post's title. */}

        <div style={{ display: "flex", gap: "10px" }}>
          {/* Container for bookmark and delete buttons */}

          {userInfo?.id && (
            <button onClick={handleBookmark} style={{ background: "none", border: "none", cursor: "pointer" }} title="Bookmark">
              {bookmarked ? (
                <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48">
                  <path fill="#A35C7A" d="M37,43l-13-6l-13,6V9c0-2.2,1.8-4,4-4h18c2.2,0,4,1.8,4,4V43z"></path>
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="24" height="24" viewBox="0 0 48 48">
                  <path fill="#ccc" d="M37,43l-13-6l-13,6V9c0-2.2,1.8-4,4-4h18c2.2,0,4,1.8,4,4V43z"></path>
                </svg>
              )}
            </button>
          )}

          {isAuthor && (
            <button onClick={handleDelete} style={{ background: "none", border: "none", cursor: "pointer" }} title="Delete Post">
              <img src="https://cdn-icons-png.flaticon.com/512/6861/6861362.png" alt="Delete" width={24} />
            </button>
          )}
        </div>
      </div>

      <time>{formatISO9075(new Date(postInfo.createdAt))}</time>
      {/* Display the formatted creation date of the post using `formatISO9075`. */}

      <div className="author">by @{postInfo.author.username}</div>
      {/* Display the author's username. */}

      {isAuthor && (
        <div className="edit-row">
          <Link className="edit-btn" to={`/edit/${postInfo._id}`}>
            Edit this post
          </Link>
        </div>
      )}
      {/* Display an "Edit this post" link if the logged-in user is the author. */}

      <div className="image">
        <img src={`http://localhost:4000/${postInfo.cover}`} alt="Post cover" />
      </div>
      {/* Display the cover image of the post. */}

      <div className="content" dangerouslySetInnerHTML={{ __html: postInfo.content }} />
      {/* Render the post content using `dangerouslySetInnerHTML` to allow HTML content (e.g., rich text). */}
    </div>
  );
}
