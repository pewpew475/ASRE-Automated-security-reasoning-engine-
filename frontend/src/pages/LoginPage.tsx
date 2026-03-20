import { Shield } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import type { AxiosError } from "axios";

import { useAuthStore } from "@/store/authStore";

export function LoginPage() {
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);
  const isLoading = useAuthStore((s) => s.isLoading);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      await login(email, password);
      navigate("/dashboard");
    } catch (error) {
      const axiosError = error as AxiosError<{ detail?: unknown }>;
      const detail = axiosError.response?.data?.detail;
      if (typeof detail === "string") {
        toast.error(detail);
        return;
      }
      toast.error("Invalid email or password");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary px-4">
      <form onSubmit={onSubmit} className="w-full max-w-md rounded-xl border border-bg-tertiary bg-bg-secondary p-6 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-lg bg-brand/15 p-2 text-brand">
            <Shield className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">ASRE</h1>
            <p className="text-sm text-text-secondary">Automated Security Reasoning Engine</p>
          </div>
        </div>

        <label className="mb-3 block text-sm text-text-secondary">
          Email
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-lg border border-bg-tertiary bg-bg-primary px-3 py-2 text-text-primary outline-none focus:border-brand"
          />
        </label>

        <label className="mb-4 block text-sm text-text-secondary">
          Password
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg border border-bg-tertiary bg-bg-primary px-3 py-2 text-text-primary outline-none focus:border-brand"
          />
        </label>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full rounded-lg bg-brand px-4 py-2 font-semibold text-bg-primary transition hover:bg-brand-dark disabled:opacity-60"
        >
          {isLoading ? "Signing In..." : "Sign In"}
        </button>

        <p className="mt-4 text-center text-sm text-text-secondary">
          Don&apos;t have an account? <Link to="/register" className="text-brand">Register</Link>
        </p>
      </form>
    </div>
  );
}
