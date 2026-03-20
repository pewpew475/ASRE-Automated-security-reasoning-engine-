import axios, { AxiosError } from "axios";
import toast from "react-hot-toast";

type ValidationDetailItem = {
  msg?: string;
};

type ErrorPayload = {
  detail?: unknown;
};

type RetryableRequestConfig = {
  _retry?: boolean;
};

const accessTokenKey = "asre_access_token";
const refreshTokenKey = "asre_refresh_token";

function getValidationMessage(detail: unknown): string {
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as ValidationDetailItem;
    if (typeof first?.msg === "string" && first.msg.trim().length > 0) {
      return first.msg;
    }
  }

  if (typeof detail === "string" && detail.trim().length > 0) {
    return detail;
  }

  return "Validation error";
}

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8010/api",
  withCredentials: true,
});

const rawClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8010/api",
  withCredentials: true,
});

let refreshPromise: Promise<string | null> | null = null;

function clearStoredAuth(): void {
  localStorage.removeItem(accessTokenKey);
  localStorage.removeItem(refreshTokenKey);
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = localStorage.getItem(refreshTokenKey);
  if (!refreshToken) {
    return null;
  }

  if (!refreshPromise) {
    refreshPromise = rawClient
      .post("/auth/refresh", { refresh_token: refreshToken })
      .then((res) => {
        const nextAccess = String(res.data?.access_token || "");
        const nextRefresh = String(res.data?.refresh_token || refreshToken);
        if (!nextAccess) {
          return null;
        }
        localStorage.setItem(accessTokenKey, nextAccess);
        localStorage.setItem(refreshTokenKey, nextRefresh);
        return nextAccess;
      })
      .catch(() => {
        clearStoredAuth();
        return null;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }

  return refreshPromise;
}

export async function getValidAccessToken(): Promise<string | null> {
  const current = localStorage.getItem(accessTokenKey);
  if (current) {
    return current;
  }
  return refreshAccessToken();
}

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem(accessTokenKey);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ErrorPayload>) => {
    const status = error.response?.status;
    const originalRequest = (error.config || {}) as typeof error.config & RetryableRequestConfig;
    const requestUrl = String(originalRequest?.url || "");

    if (
      status === 401 &&
      !originalRequest._retry &&
      !requestUrl.includes("/auth/login") &&
      !requestUrl.includes("/auth/register") &&
      !requestUrl.includes("/auth/refresh")
    ) {
      originalRequest._retry = true;
      return refreshAccessToken().then((token) => {
        if (token && originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        }

        clearStoredAuth();
        if (window.location.pathname !== "/login") {
          window.location.href = "/login";
        }
        return Promise.reject(error);
      });
    }

    if (status === 401) {
      clearStoredAuth();
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    if (status === 422) {
      toast.error(getValidationMessage(error.response?.data?.detail));
      // eslint-disable-next-line no-console
      console.error("422 details", error.response?.data);
    }
    if (status === 500) {
      toast.error("Server error - check backend logs");
    }
    return Promise.reject(error);
  }
);

export default apiClient;
