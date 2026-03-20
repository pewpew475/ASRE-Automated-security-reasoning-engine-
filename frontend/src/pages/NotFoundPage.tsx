import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <div className="flex min-h-[70vh] flex-col items-center justify-center text-center">
      <h1 className="text-4xl font-bold">404</h1>
      <p className="mt-2 text-text-secondary">Page not found.</p>
      <Link to="/dashboard" className="mt-4 rounded bg-brand px-4 py-2 font-medium text-bg-primary">
        Back to Dashboard
      </Link>
    </div>
  );
}
