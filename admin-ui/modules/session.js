// Visibility of the login/admin screens and displayed version.
import { $ } from "./dom.js";
import { startLoginNetworkCanvas } from "./login-canvas.js";
import { api } from "./api.js";

async function openSession() {
  const session = await api("/api/session");
  if (!session.authenticated && session.password_required === false) {
    await api("/api/login", {method: "POST", body: "{}"});
    session.authenticated = true;
  }
  return session;
}

function showLogin() {
  $("app-shell").classList.add("login-mode");
  $("sidebar").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  $("admin-view").classList.add("hidden");
  startLoginNetworkCanvas();
}

function showAdmin(passwordRequired = true) {
  $("app-shell").classList.remove("login-mode");
  $("sidebar").classList.remove("hidden");
  $("login-view").classList.add("hidden");
  $("admin-view").classList.remove("hidden");
  $("logout-btn").classList.toggle("hidden", !passwordRequired);
}

function setVersion(version) {
  const value = version ? `v${version}` : "v-";
  $("version").textContent = value;
  $("login-footer-version").textContent = value;
  $("admin-footer-version").textContent = value;
}

export { openSession, setVersion, showAdmin, showLogin };
