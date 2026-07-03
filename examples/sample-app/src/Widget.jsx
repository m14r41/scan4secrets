export default function Widget({ html }) {
  // XSS via dangerouslySetInnerHTML (CWE-79)
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
