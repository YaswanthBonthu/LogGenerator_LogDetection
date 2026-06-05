export default function Toast({ message, type = 'ok' }) {
  if (!message) return null;
  return <div className={`toast show ${type}`}>{message}</div>;
}
