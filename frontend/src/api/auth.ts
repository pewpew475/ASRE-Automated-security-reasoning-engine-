import apiClient from "@/api/client";
import type { User } from "@/types";

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export const authApi = {
  login: (data: LoginRequest) => apiClient.post<AuthResponse>("/auth/login", data),
  register: (data: RegisterRequest) => apiClient.post<AuthResponse>("/auth/register", data),
  me: () => apiClient.get<User>("/auth/me"),
  logout: () => apiClient.post("/auth/logout"),
};
