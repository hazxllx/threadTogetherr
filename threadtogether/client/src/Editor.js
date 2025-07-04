import ReactQuill from "react-quill"; // Import ReactQuill for rich text editing

// Editor component receives value and onChange props
export default function Editor({ value, onChange }) {
  // Define toolbar options for ReactQuill (text formatting options)
  const modules = {
    toolbar: [
      [{ header: [1, 2, false] }], // Header options (h1, h2, and no header)
      ['bold', 'italic', 'underline', 'strike', 'blockquote'], // Text formatting options (bold, italic, underline, strike-through, blockquote)
      [
        { list: 'ordered' }, // Ordered list
        { list: 'bullet' }, // Unordered list (bullet points)
        { indent: '-1' }, // Decrease indent
        { indent: '+1' }, // Increase indent
      ],
      ['link', 'image'], // Add link and image options
      ['clean'], // Clean (reset formatting) button
    ],
  };

  return (
    <div className="content">
      {/* Render ReactQuill editor with specified props */}
      <ReactQuill
        value={value} // Bind the editor's value to the passed `value` prop
        theme={'snow'} // Set the theme to 'snow' (default theme)
        onChange={onChange} // Call the onChange function passed as a prop whenever content changes
        modules={modules} // Pass the toolbar options defined above
      />
    </div>
  );
}
