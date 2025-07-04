import { useState } from "react"; 
// Import `useState` hook to manage the component's state (for storing username and password).
import { useNavigate } from "react-router-dom"; 
// Import `useNavigate` from `react-router-dom` to programmatically navigate to other pages after successful registration.

export default function RegisterPage() { 
  // Define the `RegisterPage` component as the default export.

  const [username, setUsername] = useState(''); 
  // `username` state variable to store the value of the username input. Initially set to an empty string.

  const [password, setPassword] = useState(''); 
  // `password` state variable to store the value of the password input. Initially set to an empty string.

  const navigate = useNavigate(); 
  // `navigate` function allows programmatic navigation, which we will use to redirect the user after registration.

  async function register(ev) { 
    // Define the `register` function to handle the registration process when the form is submitted.

    ev.preventDefault(); 
    // Prevent the default form submission behavior (e.g., page reload).

    const response = await fetch('http://localhost:4000/register', { 
      // Send a POST request to the server to register the user.

      method: 'POST', 
      // The HTTP method is `POST` as we are sending data to create a new user.

      body: JSON.stringify({ username, password }), 
      // The request body contains the username and password in JSON format.

      headers: { 'Content-Type': 'application/json' }, 
      // Set the `Content-Type` header to `application/json` because we're sending JSON data.
    });

    if (response.status === 200) { 
      // If the response status is 200 (OK), registration is successful.
      
      alert('Registration successful'); 
      // Show a success message to the user.

      navigate('/'); 
      // Redirect the user to the homepage (or login page) after successful registration.
    } else { 
      alert('Registration failed'); 
      // If the registration fails, show an error message.
    }
  }

  return (
    <form className="register" onSubmit={register}>
      {/* The form element for the registration page. When the form is submitted, `register` function is triggered. */}

      <h1>Register</h1>
      {/* Heading for the registration page. */}

      <input
        type="text"
        placeholder="username"
        value={username}
        onChange={(ev) => setUsername(ev.target.value)}
      />
      {/* Input field for the username. The `value` is controlled by the `username` state, and the `onChange` handler updates it. */}

      <input
        type="password"
        placeholder="password"
        value={password}
        onChange={(ev) => setPassword(ev.target.value)}
      />
      {/* Input field for the password. The `value` is controlled by the `password` state, and the `onChange` handler updates it. */}

      <button>Register</button>
      {/* Submit button to trigger the form submission and call the `register` function. */}
    </form>
  );
}
