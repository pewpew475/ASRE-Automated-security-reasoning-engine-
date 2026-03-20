import { useEffect, useMemo } from "react";

import { useAuthStore } from "@/store/authStore";

function parseJwtExp(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) {
      return null;
    }
    const decoded = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))) as { exp?: number };
    return typeof decoded.exp === "number" ? decoded.exp : null;
  } catch {
    return null;
  }
}

export function useAuth() {
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const isLoading = useAuthStore((s) => s.isLoading);
  const login = useAuthStore((s) => s.login);
  const logout = useAuthStore((s) => s.logout);
  const loadUser = useAuthStore((s) => s.loadUser);

  useEffect(() => {
    if (!token) {
      return;
    }
    const exp = parseJwtExp(token);
    if (exp && exp < Date.now() / 1000) {
      logout();
      return;
    }
    void loadUser();
  }, [token, loadUser, logout]);

  const isAuthenticated = useMemo(() => Boolean(token), [token]);

  return {
    user,
    token,
    isAuthenticated,
    login,
    logout,
    isLoading,
  };
}
