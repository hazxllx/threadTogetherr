import 'react-quill/dist/quill.snow.css'; 
// Import the CSS file for the React Quill editor (with the "snow" theme), which is used for rich text editing.

import { useState } from "react"; 
// Import `useState` hook to manage the state of variables such as `title`, `summary`, `content`, `files`, and `redirect`.

import { Navigate } from "react-router-dom"; 
// Import `Navigate` from `react-router-dom` to programmatically redirect the user after successfully creating a post.

import Editor from "../Editor"; 
// Import the `Editor` component, which is used for handling rich text input for the post content.

export default function CreatePost() { 
  // Declare the `CreatePost` component as the default export of the file.

  const [title, setTitle] = useState(''); 
  // Declare the `title` state variable to store the title of the post. Initially, it is set to an empty string.
  
  const [summary, setSummary] = useState(''); 
  // Declare the `summary` state variable to store the summary of the post. Initially, it is set to an empty string.

  const [content, setContent] = useState(''); 
  // Declare the `content` state variable to store the content of the post (rich text). Initially, it is set to an empty string.

  const [files, setFiles] = useState(''); 
  // Declare the `files` state variable to store the files selected by the user (e.g., cover image). Initially, it is set to an empty string.

  const [redirect, setRedirect] = useState(false); 
  // Declare the `redirect` state variable to control the redirection after a successful post creation. Initially, it is set to `false`.

  async function createNewPost(ev) { 
    // Declare an asynchronous function `createNewPost` to handle the form submission.

    const data = new FormData(); 
    // Create a new `FormData` object to handle the form data, including file uploads.

    data.set('title', title); 
    // Add the `title` value to the `FormData` object.

    data.set('summary', summary); 
    // Add the `summary` value to the `FormData` object.

    data.set('content', content); 
    // Add the `content` value to the `FormData` object.

    data.set('file', files[0]); 
    // Add the first file from the `files` state to the `FormData` object. `files[0]` is used because files are stored in an array-like object.

    ev.preventDefault(); 
    // Prevent the default form submission behavior (page reload).

    const response = await fetch('http://localhost:4000/post', { 
      // Send a `POST` request to the server to create a new post.
      method: 'POST', 
      // Specify the HTTP method as `POST`.

      body: data, 
      // Attach the `FormData` object as the body of the request to send the form data to the server.

      credentials: 'include', 
      // Include cookies (such as session tokens) in the request for authentication.
    });

    if (response.ok) { 
      // If the response is successful (status code 200-299),
      setRedirect(true); 
      // Set the `redirect` state to `true`, indicating that the post was successfully created and the user should be redirected.
    }
  }

  if (redirect) { 
    // If the `redirect` state is `true`,
    return <Navigate to={'/'} />; 
    // Redirect the user to the homepage (`/`) using the `Navigate` component from `react-router-dom`.
  }

  return ( 
    // Render the form to create a new post.

    <form onSubmit={createNewPost}> 
      {/* On form submission, call `createNewPost` to handle the data and send the request to the server. */}

      <input 
        type="title" 
        placeholder={'Title'} 
        value={title} 
        onChange={ev => setTitle(ev.target.value)} 
      />
      {/* Input field for the post's title. The value is controlled by the `title` state, and changes are handled by `setTitle`. */}

      <input 
        type="summary" 
        placeholder={'Summary'} 
        value={summary} 
        onChange={ev => setSummary(ev.target.value)} 
      />
      {/* Input field for the post's summary. The value is controlled by the `summary` state, and changes are handled by `setSummary`. */}

      <input 
        type="file" 
        onChange={ev => setFiles(ev.target.files)} 
      />
      {/* File input for selecting files (e.g., cover image). The `onChange` event updates the `files` state with the selected files. */}

      <Editor value={content} onChange={setContent} /> 
      {/* The `Editor` component is used for rich text input. The `value` is bound to the `content` state, and changes are handled by `setContent`. */}

      <button style={{ marginTop: '5px' }}>Create post</button> 
      {/* Submit button to trigger the form submission. When clicked, it triggers the `createNewPost` function. */}
    </form>
  );
}
