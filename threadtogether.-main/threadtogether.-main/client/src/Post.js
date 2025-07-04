import React from 'react'; // React library
import { Link } from 'react-router-dom'; // Import Link for navigation
import { formatISO9075 } from 'date-fns'; // Import date-fns to format the date

export default function Post({ _id, title, summary, cover, createdAt, author }) {
  return (
    <div className="post"> {/* Wrapper for individual post */}
      <div className="image">
        {/* Link to the full post page using the post's ID */}
        <Link to={`/post/${_id}`}>
          {/* Display the post cover image */}
          <img src={`http://localhost:4000/${cover}`} alt="Post cover" />
        </Link>
      </div>
      <div className="texts">
        {/* Link to the full post page using the post's ID */}
        <Link to={`/post/${_id}`}>
          {/* Display the post title */}
          <h2>{title}</h2>
        </Link>
        <p className="info">
          {/* Display the author's username (if available) */}
          <span className="author">{author?.username}</span>
          {/* Format and display the post creation date */}
          <time>{formatISO9075(new Date(createdAt))}</time> {/* Date formatted as ISO 9075 */}
        </p>
        {/* Display the post summary */}
        <p className="summary">{summary}</p>
      </div>
    </div>
  );
}
