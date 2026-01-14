/**
 * FastAPI Cognito - Frontend Application
 * Minimal JS that calls Python backend for authentication
 */

// DOM Elements
const loginContainer = document.getElementById("login-container");
const dashboardContainer = document.getElementById("dashboard-container");
const forms = {
  login: { form: document.getElementById("login-form"), box: document.querySelector(".form-box.login") },
  forgot: { form: document.getElementById("forgot-form"), box: document.querySelector(".form-box.forgot") },
  reset: { form: document.getElementById("reset-form"), box: document.querySelector(".form-box.reset") },
  newPassword: { form: document.getElementById("new-password-form"), box: document.querySelector(".form-box.new-password") },
};

let pendingEmail = "";

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
});

function setupEventListeners() {
  forms.login.form.addEventListener("submit", handleLogin);
  forms.forgot.form.addEventListener("submit", handleForgotPassword);
  forms.reset.form.addEventListener("submit", handleResetPassword);
  forms.newPassword.form.addEventListener("submit", handleNewPassword);

  document.getElementById("show-forgot").addEventListener("click", (e) => { e.preventDefault(); showForm("forgot"); });
  document.getElementById("show-login").addEventListener("click", (e) => { e.preventDefault(); showForm("login"); });
  document.getElementById("logout-btn").addEventListener("click", handleLogout);
  document.getElementById("test-api-btn").addEventListener("click", testApi);
}

function showForm(name) {
  Object.values(forms).forEach(f => { f.box.classList.remove("active"); f.box.classList.add("hidden"); });
  forms[name].box.classList.remove("hidden");
  forms[name].box.classList.add("active");
  clearErrors();
}

function clearErrors() {
  document.querySelectorAll(".error-message").forEach(el => el.textContent = "");
}

function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg;
}

function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.classList.toggle("loading", loading);
}

async function apiCall(endpoint, data) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
    credentials: "same-origin",
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.detail || "Error desconocido");
  return json;
}

async function handleLogin(e) {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  setLoading(btn, true);

  try {
    const data = await apiCall("/auth/login", {
      email: document.getElementById("login-email").value,
      password: document.getElementById("login-password").value,
    });

    if (data.requires_new_password) {
      pendingEmail = data.email;
      showForm("newPassword");
    } else {
      showDashboard(data.email);
    }
  } catch (err) {
    showError("login-error", err.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleNewPassword(e) {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  const newPass = document.getElementById("new-password").value;
  const confirm = document.getElementById("new-password-confirm").value;

  if (newPass !== confirm) {
    showError("new-password-error", "Las contraseñas no coinciden");
    return;
  }

  setLoading(btn, true);
  try {
    const data = await apiCall("/auth/new-password", {
      email: pendingEmail,
      temporary_password: document.getElementById("login-password").value,
      new_password: newPass,
    });
    showDashboard(data.email);
  } catch (err) {
    showError("new-password-error", err.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleForgotPassword(e) {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  setLoading(btn, true);

  try {
    const email = document.getElementById("forgot-email").value;
    await apiCall("/auth/forgot-password", { email });
    pendingEmail = email;
    showForm("reset");
  } catch (err) {
    showError("forgot-error", err.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleResetPassword(e) {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  const newPass = document.getElementById("reset-password").value;
  const confirm = document.getElementById("reset-confirm").value;

  if (newPass !== confirm) {
    showError("reset-error", "Las contraseñas no coinciden");
    return;
  }

  setLoading(btn, true);
  try {
    await apiCall("/auth/reset-password", {
      email: pendingEmail,
      code: document.getElementById("reset-code").value,
      new_password: newPass,
    });
    alert("Contraseña restablecida correctamente");
    showForm("login");
  } catch (err) {
    showError("reset-error", err.message);
  } finally {
    setLoading(btn, false);
  }
}

async function showDashboard(email) {
  loginContainer.style.display = "none";
  dashboardContainer.style.display = "flex";
  document.getElementById("user-email").textContent = email || "Usuario";
  document.getElementById("user-sub").textContent = "Cargando...";

  // Fetch user profile to get sub
  try {
    const res = await fetch("/users/me", { credentials: "same-origin" });
    if (res.ok) {
      const data = await res.json();
      document.getElementById("user-sub").textContent = data.sub || "-";
    }
  } catch {
    document.getElementById("user-sub").textContent = "-";
  }
}

async function handleLogout() {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  dashboardContainer.style.display = "none";
  loginContainer.style.display = "flex";
  showForm("login");
  document.querySelectorAll("input").forEach(i => i.value = "");
}

async function testApi() {
  const el = document.getElementById("api-response");
  try {
    const res = await fetch("/users/me", { credentials: "same-origin" });
    const data = await res.json();
    el.className = "api-response " + (res.ok ? "success" : "error");
    el.textContent = JSON.stringify(data, null, 2);
    if (res.ok) document.getElementById("user-sub").textContent = data.sub || "-";
  } catch (err) {
    el.className = "api-response error";
    el.textContent = err.message;
  }
}
