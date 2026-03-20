import axios, { AxiosError } from "axios";
import toast from "react-hot-toast";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000/api",
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("asre_access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: unknown }>) => {
    const status = error.response?.status;
    if (status === 401) {
      localStorage.removeItem("asre_access_token");
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    if (status === 422) {
      toast.error("Validation error");
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
