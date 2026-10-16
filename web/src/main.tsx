import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import "./index.css";
import { AuthProvider, useAuth } from "./lib/auth";
import { LiveProvider } from "./lib/live";
import { ThemeProvider } from "./lib/theme";
import { Spinner, ToastProvider } from "./components/ui";
import { Layout } from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Sites from "./pages/Sites";
import IPRules from "./pages/IPRules";
import Notifications from "./pages/Notifications";
import Users from "./pages/Users";
import Audit from "./pages/Audit";
import Account from "./pages/Account";

function App() {
  const { user, loading, isAdmin } = useAuth();
  if (loading) return <Spinner />;
  if (!user) return <Login />;
  return (
    <LiveProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="events" element={<Events />} />
          <Route path="sites" element={<Sites />} />
          <Route path="ip-rules" element={<IPRules />} />
          {isAdmin && <Route path="notifications" element={<Notifications />} />}
          {isAdmin && <Route path="users" element={<Users />} />}
          {isAdmin && <Route path="audit" element={<Audit />} />}
          <Route path="account" element={<Account />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </LiveProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <AuthProvider>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  </StrictMode>,
);
