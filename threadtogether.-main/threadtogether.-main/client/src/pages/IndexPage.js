import Post from "../Post"; 
// Importing the `Post` component which is used to display each individual post. The `Post` component will receive post data as props.

import { useEffect, useState } from "react"; 
// Importing `useState` to manage the state for the list of posts, and `useEffect` to perform side effects (fetching data from the backend).

export default function IndexPage() { 
  // Define the `IndexPage` component which is responsible for displaying a list of posts.

  const [posts, setPosts] = useState([]); 
  // Declare the `posts` state variable to store the list of posts fetched from the server. Initially, it's set to an empty array.
  
  useEffect(() => { 
    // `useEffect` hook to fetch data when the component mounts.

    fetch('http://localhost:4000/post') 
      // Send a GET request to the server to fetch the list of posts from the backend.

      .then(response => response.json()) 
      // Parse the response as JSON.

      .then(posts => { 
        setPosts(posts); 
        // Set the `posts` state with the fetched posts data.
      })

      .catch(error => { 
        console.error("Error fetching posts:", error); 
        // Log any errors that occur during the fetch request.
      });
  }, []); 
  // The empty dependency array `[]` ensures this effect runs only once when the component mounts.

  return (
    <>
      {posts.length > 0 ? ( 
        // If there are posts in the `posts` array, map through them and render each `Post` component.
        posts.map(post => (
          <Post key={post._id} {...post} /> 
          // For each `post`, render a `Post` component and pass the post data as props. `key={post._id}` ensures each post is uniquely identified.
        ))
      ) : ( 
        // If there are no posts available, display a message saying so.
        <p>No posts available</p>
      )}
    </>
  );
}
