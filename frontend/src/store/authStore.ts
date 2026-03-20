import { create } from "zustand";
import toast from "react-hot-toast";

import { authApi } from "@/api/auth";
import type { User } from "@/types";

interface AuthState {
  token: string | null;
  user: User | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, full_name: string) => Promise<void>;
  logout: () => void;
  loadUser: () => Promise<void>;
}

const tokenKey = "asre_access_token";

export const useAuthStore = create<AuthState>((set, get) => ({
  token: localStorage.getItem(tokenKey),
  user: null,
  isLoading: false,
  login: async (email, password) => {
    set(() => ({ isLoading: true }));
    try {
      const { data } = await authApi.login({ email, password });
      localStorage.setItem(tokenKey, data.access_token);
      set(() => ({ token: data.access_token, user: data.user, isLoading: false }));
      toast.success("Welcome back");
    } catch (error) {
      set(() => ({ isLoading: false }));
      throw error;
    }
  },
  register: async (email, password, full_name) => {
    set(() => ({ isLoading: true }));
    try {
      const { data } = await authApi.register({ email, password, full_name });
      localStorage.setItem(tokenKey, data.access_token);
      set(() => ({ token: data.access_token, user: data.user, isLoading: false }));
      toast.success("Account created");
    } catch (error) {
      set(() => ({ isLoading: false }));
      throw error;
    }
  },
  logout: () => {
    localStorage.removeItem(tokenKey);
    set(() => ({ token: null, user: null }));
    window.location.href = "/login";
  },
  loadUser: async () => {
    const token = get().token;
    if (!token) {
      return;
    }
    set(() => ({ isLoading: true }));
    try {
      const { data } = await authApi.me();
      set(() => ({ user: data, isLoading: false }));
    } catch {
      localStorage.removeItem(tokenKey);
      set(() => ({ token: null, user: null, isLoading: false }));
    }
  },
}));
