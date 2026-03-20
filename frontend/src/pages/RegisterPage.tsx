import { ShieldCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import type { AxiosError } from "axios";

import { useAuthStore } from "@/store/authStore";

export function RegisterPage() {
  const navigate = useNavigate();
  const register = useAuthStore((s) => s.register);
  const isLoading = useAuthStore((s) => s.isLoading);

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const normalizedEmail = email.trim();
    const normalizedFullName = fullName.trim();

    if (password.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }
    if (!/[A-Z]/.test(password)) {
      toast.error("Password must contain at least one uppercase letter");
      return;
    }
    if (!/\d/.test(password)) {
      toast.error("Password must contain at least one digit");
      return;
    }
    if (password !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }

    try {
      await register(normalizedEmail, password, normalizedFullName);
      toast.success("Account created");
      navigate("/dashboard");
    } catch (error) {
      const axiosError = error as AxiosError<{ detail?: unknown }>;
      const detail = axiosError.response?.data?.detail;
      if (Array.isArray(detail) && detail[0] && typeof detail[0] === "object" && "msg" in detail[0]) {
        toast.error(String((detail[0] as { msg?: string }).msg || "Registration failed"));
        return;
      }
      if (typeof detail === "string") {
        toast.error(detail);
        return;
      }
      toast.error("Registration failed");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary px-4">
      <form onSubmit={onSubmit} className="w-full max-w-md rounded-xl border border-bg-tertiary bg-bg-secondary p-6 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-lg bg-brand/15 p-2 text-brand">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Create ASRE Account</h1>
            <p className="text-sm text-text-secondary">Secure your local-first security workflow</p>
          </div>
        </div>

        <label className="mb-3 block text-sm text-text-secondary">
          Full Name
          <input
            required
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            className="mt-1 w-full rounded-lg border border-bg-tertiary bg-bg-primary px-3 py-2 text-text-primary outline-none focus:border-brand"
          />
        </label>

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

        <label className="mb-3 block text-sm text-text-secondary">
          Password
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg border border-bg-tertiary bg-bg-primary px-3 py-2 text-text-primary outline-none focus:border-brand"
          />
        </label>

        <label className="mb-4 block text-sm text-text-secondary">
          Confirm Password
          <input
            type="password"
            required
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="mt-1 w-full rounded-lg border border-bg-tertiary bg-bg-primary px-3 py-2 text-text-primary outline-none focus:border-brand"
          />
        </label>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full rounded-lg bg-brand px-4 py-2 font-semibold text-bg-primary transition hover:bg-brand-dark disabled:opacity-60"
        >
          {isLoading ? "Creating..." : "Register"}
        </button>

        <p className="mt-4 text-center text-sm text-text-secondary">
          Already have an account? <Link to="/login" className="text-brand">Sign In</Link>
        </p>
      </form>
    </div>
  );
}
