import { useEffect, useState } from "react"; 
// Import React hooks: `useState` for managing state, and `useEffect` for handling side effects (e.g., fetching data when the component mounts or when dependencies change).

import { Navigate, useParams } from "react-router-dom"; 
// Import `Navigate` to programmatically redirect the user after updating a post, and `useParams` to extract the `id` from the URL (used to identify the post to edit).

import Editor from "../Editor"; 
// Import the `Editor` component for handling rich-text editing of the post content.

export default function EditPost() { 
  // Define the `EditPost` component as the default export of the file.

  const { id } = useParams(); 
  // Use `useParams` to extract the `id` from the URL. This `id` is used to fetch the specific post to edit.

  const [title, setTitle] = useState(''); 
  // Declare the `title` state to store the title of the post being edited. Initially, it's set to an empty string.

  const [summary, setSummary] = useState(''); 
  // Declare the `summary` state to store the summary of the post being edited. Initially, it's set to an empty string.

  const [content, setContent] = useState(''); 
  // Declare the `content` state to store the content of the post (rich-text) being edited. Initially, it's set to an empty string.

  const [files, setFiles] = useState(''); 
  // Declare the `files` state to store the files (e.g., cover image) selected for uploading. Initially, it's set to an empty string.

  const [redirect, setRedirect] = useState(false); 
  // Declare the `redirect` state to control the redirection after the post has been updated. Initially, it's set to `false`.

  useEffect(() => { 
    // `useEffect` hook is used to fetch data when the component mounts or when `id` changes.
    fetch('http://localhost:4000/post/' + id) 
      // Send a GET request to fetch the post data by its `id`.
      .then(response => {
        response.json().then(postInfo => {
          setTitle(postInfo.title); 
          // Set the `title` state with the fetched post title.

          setContent(postInfo.content); 
          // Set the `content` state with the fetched post content.

          setSummary(postInfo.summary); 
          // Set the `summary` state with the fetched post summary.
        });
      });
  }, [id]); 
  // The dependency array includes `id`, meaning the effect will re-run whenever `id` changes.

  async function updatePost(ev) { 
    // Define the `updatePost` function to handle the form submission and update the post data.

    ev.preventDefault(); 
    // Prevent the default form submission behavior (e.g., page reload).

    const data = new FormData(); 
    // Create a `FormData` object to send the form data, including any file uploads.

    data.set('title', title); 
    // Add the `title` state value to the `FormData` object.

    data.set('summary', summary); 
    // Add the `summary` state value to the `FormData` object.

    data.set('content', content); 
    // Add the `content` state value to the `FormData` object.

    data.set('id', id); 
    // Add the `id` to the `FormData` object, identifying the post to be updated.

    if (files?.[0]) { 
      // If a file is selected (check if `files` has at least one file),
      data.set('file', files?.[0]); 
      // Add the selected file to the `FormData` object.
    }

    const response = await fetch('http://localhost:4000/post', { 
      // Send a PUT request to the server to update the post data.
      method: 'PUT', 
      // Use the `PUT` method to update an existing post.
      
      body: data, 
      // Attach the `FormData` object as the body of the request (including the title, summary, content, and file).

      credentials: 'include', 
      // Include cookies (such as session cookies) to authenticate the user.
    });

    if (response.ok) { 
      // If the response is successful (status code 200-299),
      setRedirect(true); 
      // Set the `redirect` state to `true`, which will trigger a redirection to the updated post.
    }
  }

  if (redirect) { 
    // If the `redirect` state is `true` (indicating the post has been updated),
    return <Navigate to={'/post/' + id} />; 
    // Redirect the user to the updated post page using the `Navigate` component.
  }

  return ( 
    // Render the form for editing the post.

    <form onSubmit={updatePost}> 
      {/* On form submission, call the `updatePost` function to handle the data update. */}

      <input 
        type="title" 
        placeholder={'Title'} 
        value={title} 
        onChange={ev => setTitle(ev.target.value)} 
      />
      {/* Input field for the post's title. The `value` is controlled by the `title` state, and changes are handled by `setTitle`. */}

      <input 
        type="summary" 
        placeholder={'Summary'} 
        value={summary} 
        onChange={ev => setSummary(ev.target.value)} 
      />
      {/* Input field for the post's summary. The `value` is controlled by the `summary` state, and changes are handled by `setSummary`. */}

      <input 
        type="file" 
        onChange={ev => setFiles(ev.target.files)} 
      />
      {/* File input for selecting files (e.g., cover image). The `onChange` event updates the `files` state with the selected files. */}

      <Editor onChange={setContent} value={content} /> 
      {/* The `Editor` component for rich text input. The `value` is bound to the `content` state, and `onChange` updates the `content` state with the editor's value. */}

      <button style={{ marginTop: '5px' }}>Update post</button> 
      {/* Submit button to trigger the form submission. It will call the `updatePost` function when clicked. */}
    </form>
  );
}
