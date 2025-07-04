import React, { useState, useEffect, useContext } from "react"; 
// Importing necessary React hooks: `useState` to manage state, `useEffect` for side effects (data fetching), 
// and `useContext` to access values from `UserContext`.

import { UserContext } from "../UserContext"; 
// Importing `UserContext` to access user-related information, like authentication status (i.e., whether the user is logged in).

import { Link } from "react-router-dom"; 
// Importing `Link` from `react-router-dom` to handle navigation between pages without reloading the entire page.

import { formatISO9075 } from "date-fns"; 
// Importing `formatISO9075` from `date-fns` for formatting dates into an easily readable ISO format (e.g., YYYY-MM-DD).

export default function Bookmark() { 
  // Declare the `Bookmark` component as the default export of the file.

  const [bookmarks, setBookmarks] = useState([]); 
  // `bookmarks` state variable to store the list of bookmarked posts. Initially, it's an empty array.
  // `setBookmarks` is the function used to update this state.

  const { userInfo } = useContext(UserContext); 
  // Using the `useContext` hook to access the current user's information (authentication data) from `UserContext`.

  useEffect(() => { 
    // `useEffect` hook is used for side effects. In this case, it fetches the list of bookmarks when `userInfo` changes.
    
    if (userInfo?.id) { 
      // If the `userInfo` exists and has an `id` (i.e., the user is logged in),
      
      fetch("http://localhost:4000/bookmarked-posts", { 
        // Send a GET request to the server to fetch the user's bookmarked posts.
        
        credentials: "include", 
        // Include cookies in the request (such as session cookies) for authentication.
      })
        .then((res) => res.json()) 
        // Parse the response as JSON.
        .then((data) => { 
          setBookmarks(data); 
          // Set the `bookmarks` state with the fetched data (the list of bookmarked posts).
        })
        .catch((err) => console.error("Error fetching bookmarks:", err)); 
        // Log an error if the request fails.
    }
  }, [userInfo]); 
  // This effect runs when `userInfo` changes (e.g., user logs in or logs out).

  if (!userInfo?.id) { 
    // If the user is not logged in (i.e., `userInfo` does not have an `id`), show a message.
    return <div>You need to be logged in to view your bookmarks.</div>; 
    // Display a message informing the user that they need to log in to view their bookmarks.
  }

  return ( 
    // Render the component if the user is logged in.

    <div className="bookmarks-page"> 
      {/* Wrapper div for the bookmarks page. */}
      <h1>Your Bookmarked Posts</h1> 
      {/* Display the title of the bookmarks page. */}

      <div className="bookmarks-list"> 
        {/* Wrapper div for displaying the list of bookmarked posts. */}

        {bookmarks.length === 0 ? ( 
          // Check if the `bookmarks` array is empty.
          <p>You have no bookmarks yet.</p> 
          // If there are no bookmarks, display a message to the user.
        ) : ( 
          // If there are bookmarks, map over the `bookmarks` array and render each one.
          bookmarks.map((bookmark) => ( 
            <div key={bookmark._id} className="post">  
              {/* Each bookmark is displayed in a `div`. Use `bookmark._id` as the unique `key` for each item. */}
              
              <Link to={`/post/${bookmark._id}`} className="bookmark-item">
                {/* `Link` component navigates to the individual post page using `bookmark._id` to construct the URL. */}

                <div className="image"> 
                  {/* Wrapper for displaying the cover image of the post. */}
                  <img 
                    src={`http://localhost:4000/${bookmark.cover}`} 
                    alt="Post cover" 
                    // The cover image URL is dynamically generated using the `bookmark.cover` field.
                  />
                </div>

                <div className="texts"> 
                  {/* Wrapper for the text content of the post. */}
                  
                  <h2>{bookmark.title}</h2> 
                  {/* Display the title of the bookmarked post. */}

                  <p className="info"> 
                    {/* Wrapper for the post's metadata (author and date). */}
                    <span className="author">{bookmark.author?.username}</span> 
                    {/* Display the author's username. Handle potential `undefined` values with optional chaining (`?.`). */}
                    <time>{formatISO9075(new Date(bookmark.createdAt))}</time> 
                    {/* Display the creation date of the post, formatted using `formatISO9075` for better readability. */}
                  </p>

                  <p className="summary">{bookmark.summary}</p> 
                  {/* Display the summary of the post (short preview of its content). */}
                </div>

              </Link>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
