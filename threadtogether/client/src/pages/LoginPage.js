import { useContext, useState } from "react"; 
// Import React hooks: `useState` to manage state variables like `username`, `password`, and `redirect`,
// and `useContext` to consume context (in this case, to access and update `UserContext`).

import { Navigate } from "react-router-dom"; 
// Import `Navigate` from `react-router-dom` to programmatically redirect the user after a successful login.

import { UserContext } from "../UserContext"; 
// Import `UserContext` to get and set the user-related information (such as authentication details) across the app.

export default function LoginPage() { 
  // Define the `LoginPage` component as the default export of the file.

  const [username, setUsername] = useState(''); 
  // Declare the `username` state to store the user's input for the username. Initially set to an empty string.

  const [password, setPassword] = useState(''); 
  // Declare the `password` state to store the user's input for the password. Initially set to an empty string.

  const [redirect, setRedirect] = useState(false); 
  // Declare the `redirect` state to control the redirection after a successful login. Initially set to `false`.

  const { setUserInfo } = useContext(UserContext); 
  // Use `useContext` to get the `setUserInfo` function from `UserContext`, which will update the logged-in user's info.

  async function login(ev) { 
    // Define the `login` function, which will handle the form submission for logging the user in.

    ev.preventDefault(); 
    // Prevent the default form submission behavior (page reload) when the user submits the login form.

    const response = await fetch('http://localhost:4000/login', { 
      // Send a POST request to the backend to log the user in.

      method: 'POST', 
      // The HTTP method is `POST`, as we are sending login credentials to the server.

      body: JSON.stringify({ username, password }), 
      // The request body contains the `username` and `password` in JSON format.

      headers: { 'Content-Type': 'application/json' }, 
      // Set the `Content-Type` header to `application/json` as the body is JSON.

      credentials: 'include', 
      // Include cookies (such as session cookies) to handle authentication, if necessary.
    });

    if (response.ok) { 
      // If the response status is OK (status code 200-299),
      response.json().then(userInfo => { 
        // Parse the response as JSON and then update the user information in the context.

        setUserInfo(userInfo); 
        // Call `setUserInfo` to set the user's information in the global context, indicating the user is logged in.

        setRedirect(true); 
        // Set the `redirect` state to `true`, which will trigger the redirection to the home page.
      });
    } else { 
      alert('Wrong credentials'); 
      // If the response is not OK, show an alert indicating the login credentials are incorrect.
    }
  }

  if (redirect) { 
    // If `redirect` is `true` (meaning login was successful),
    return <Navigate to={'/'} />; 
    // Redirect the user to the home page (or any other route you choose) using `Navigate` from `react-router-dom`.
  }

  return (
    // Return the JSX for rendering the login form.
    <form className="login" onSubmit={login}>
      {/* The form element for the login page. When the form is submitted, it triggers the `login` function. */}

      <h1>Login</h1>
      {/* Display the login page title. */}

      <input 
        type="text" 
        placeholder="Username" 
        value={username} 
        onChange={ev => setUsername(ev.target.value)} 
      />
      {/* Input field for the username. The `value` is controlled by the `username` state, and changes are handled by `setUsername`. */}

      <input 
        type="password" 
        placeholder="Password" 
        value={password} 
        onChange={ev => setPassword(ev.target.value)} 
      />
      {/* Input field for the password. The `value` is controlled by the `password` state, and changes are handled by `setPassword`. */}

      <button>Login</button> 
      {/* Submit button to trigger the login process. It calls the `login` function on click. */}
    </form>
  );
}
