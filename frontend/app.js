"use strict";

(() => {
  const MASK = "•".repeat(10);
  const PASSWORD_CHARSET =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

  const state = { csrf: null, items: [], editingId: null };
  const $ = (id) => document.getElementById(id);

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function api(method, path, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (state.csrf && method !== "GET") headers["X-CSRF-Token"] = state.csrf;

    let response;
    try {
      response = await fetch(path, {
        method,
        headers,
        credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError(0, "Could not reach the server.");
    }

    let data = null;
    if (response.status !== 204) {
      try {
        data = await response.json();
      } catch {
        data = null;
      }
    }
    if (!response.ok) {
      const message =
        data && typeof data.detail === "string"
          ? data.detail
          : `Request failed (${response.status}).`;
      throw new ApiError(response.status, message);
    }
    return data;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function smallButton(label, onClick, extraClass) {
    const button = el("button", extraClass ? `btn small ${extraClass}` : "btn small", label);
    button.type = "button";
    button.addEventListener("click", onClick);
    return button;
  }

  function showError(id, message) {
    const node = $(id);
    node.textContent = message;
    node.hidden = false;
  }

  function clearError(id) {
    const node = $(id);
    node.textContent = "";
    node.hidden = true;
  }

  function setBusy(form, busy) {
    form.querySelectorAll("button").forEach((button) => {
      button.disabled = busy;
    });
  }

  function safeHttpUrl(raw) {
    try {
      const url = new URL(raw);
      return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
    } catch {
      return null;
    }
  }

  function generatePassword(length = 20) {
    const limit = Math.floor(256 / PASSWORD_CHARSET.length) * PASSWORD_CHARSET.length;
    const buffer = new Uint8Array(1);
    const out = [];
    while (out.length < length) {
      crypto.getRandomValues(buffer);
      if (buffer[0] < limit) out.push(PASSWORD_CHARSET[buffer[0] % PASSWORD_CHARSET.length]);
    }
    return out.join("");
  }

  async function copyText(text, button) {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => {
      button.textContent = original;
    }, 1200);
  }

  // ---- views ----------------------------------------------------------

  function showPanel(which) {
    $("login-panel").hidden = which !== "login";
    $("register-panel").hidden = which !== "register";
    clearError("auth-error");
  }

  function showAuth(message) {
    state.csrf = null;
    state.items = [];
    $("items").replaceChildren();
    $("search").value = "";
    resetItemForm();
    $("vault-view").hidden = true;
    $("session-info").hidden = true;
    $("user-email").textContent = "";
    $("auth-view").hidden = false;
    showPanel("login");
    if (message) showError("auth-error", message);
  }

  async function showVault(email) {
    $("auth-view").hidden = true;
    $("vault-view").hidden = false;
    $("session-info").hidden = false;
    $("user-email").textContent = email;
    clearError("vault-error");
    await loadItems();
  }

  function handleVaultError(err) {
    if (err.status === 401) {
      showAuth("Your session has expired. Please log in again.");
      return;
    }
    showError("vault-error", err.message);
  }

  // ---- vault list -----------------------------------------------------

  async function loadItems() {
    try {
      state.items = await api("GET", "/api/vault/items");
      clearError("vault-error");
      renderItems();
    } catch (err) {
      handleVaultError(err);
    }
  }

  function renderItems() {
    const query = $("search").value.trim().toLowerCase();
    const visible = state.items
      .filter(
        (item) =>
          !query ||
          item.title.toLowerCase().includes(query) ||
          item.username.toLowerCase().includes(query) ||
          item.url.toLowerCase().includes(query),
      )
      .sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));

    $("items").replaceChildren(...visible.map(buildItem));
    $("empty-state").hidden = visible.length > 0;
  }

  function line(label, ...nodes) {
    const row = el("div", "line");
    row.append(el("span", "label", label), ...nodes);
    return row;
  }

  function buildItem(item) {
    const node = el("li", "item");
    node.append(el("h3", undefined, item.title));

    if (item.username) {
      const copy = smallButton("Copy", () => copyText(item.username, copy));
      node.append(line("Username", el("span", "value", item.username), copy));
    }

    if (item.password) {
      const secret = el("code", "secret", MASK);
      let revealed = false;
      const toggle = smallButton("Show", () => {
        revealed = !revealed;
        secret.textContent = revealed ? item.password : MASK;
        toggle.textContent = revealed ? "Hide" : "Show";
      });
      const copy = smallButton("Copy", () => copyText(item.password, copy));
      node.append(line("Password", secret, toggle, copy));
    }

    if (item.url) {
      const href = safeHttpUrl(item.url);
      let target;
      if (href) {
        target = el("a", "value", item.url);
        target.href = href;
        target.target = "_blank";
        target.rel = "noopener noreferrer";
      } else {
        target = el("span", "value", item.url);
      }
      node.append(line("URL", target));
    }

    if (item.notes) node.append(el("p", "notes", item.notes));

    const actions = el("div", "actions");
    actions.append(
      smallButton("Edit", () => startEdit(item)),
      smallButton("Delete", () => deleteItem(item), "danger"),
    );
    node.append(actions);
    return node;
  }

  // ---- item form ------------------------------------------------------

  function resetItemForm() {
    $("item-form").reset();
    state.editingId = null;
    $("item-password").type = "password";
    $("toggle-password").textContent = "Show";
    $("form-title").textContent = "Add item";
    $("save-btn").textContent = "Save";
    $("cancel-btn").hidden = true;
  }

  function startEdit(item) {
    state.editingId = item.id;
    $("item-title").value = item.title;
    $("item-username").value = item.username;
    $("item-password").value = item.password;
    $("item-password").type = "password";
    $("toggle-password").textContent = "Show";
    $("item-url").value = item.url;
    $("item-notes").value = item.notes;
    $("form-title").textContent = "Edit item";
    $("save-btn").textContent = "Update";
    $("cancel-btn").hidden = false;
    $("item-title").focus();
  }

  async function deleteItem(item) {
    if (!window.confirm(`Delete "${item.title}"?`)) return;
    try {
      await api("DELETE", `/api/vault/items/${item.id}`);
      if (state.editingId === item.id) resetItemForm();
      await loadItems();
    } catch (err) {
      handleVaultError(err);
    }
  }

  // ---- auth -----------------------------------------------------------

  async function login(email, password) {
    const data = await api("POST", "/api/auth/login", { email, master_password: password });
    state.csrf = data.csrf_token;
    await showVault(data.email);
  }

  // ---- wiring ---------------------------------------------------------

  $("show-register").addEventListener("click", () => showPanel("register"));
  $("show-login").addEventListener("click", () => showPanel("login"));
  $("search").addEventListener("input", renderItems);
  $("cancel-btn").addEventListener("click", resetItemForm);

  $("toggle-password").addEventListener("click", () => {
    const input = $("item-password");
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    $("toggle-password").textContent = reveal ? "Hide" : "Show";
  });

  $("generate-password").addEventListener("click", () => {
    const input = $("item-password");
    input.value = generatePassword();
    input.type = "text";
    $("toggle-password").textContent = "Hide";
  });

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    clearError("auth-error");
    setBusy(form, true);
    try {
      await login($("login-email").value, $("login-password").value);
      form.reset();
    } catch (err) {
      showError("auth-error", err.message);
    } finally {
      setBusy(form, false);
    }
  });

  $("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    clearError("auth-error");

    const email = $("register-email").value;
    const password = $("register-password").value;
    if (password !== $("register-confirm").value) {
      showError("auth-error", "The two passwords do not match.");
      return;
    }

    setBusy(form, true);
    try {
      await api("POST", "/api/auth/register", { email, master_password: password });
      await login(email, password);
      form.reset();
    } catch (err) {
      showError("auth-error", err.message);
    } finally {
      setBusy(form, false);
    }
  });

  $("logout-btn").addEventListener("click", async () => {
    try {
      await api("POST", "/api/auth/logout");
    } catch {
      // The session may already have expired; the UI locks either way.
    }
    showAuth();
  });

  $("item-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    clearError("vault-error");

    const payload = {
      title: $("item-title").value,
      username: $("item-username").value,
      password: $("item-password").value,
      url: $("item-url").value,
      notes: $("item-notes").value,
    };

    setBusy(form, true);
    try {
      if (state.editingId === null) {
        await api("POST", "/api/vault/items", payload);
      } else {
        await api("PUT", `/api/vault/items/${state.editingId}`, payload);
      }
      resetItemForm();
      await loadItems();
    } catch (err) {
      handleVaultError(err);
    } finally {
      setBusy(form, false);
    }
  });

  async function init() {
    try {
      const me = await api("GET", "/api/auth/me");
      state.csrf = me.csrf_token;
      await showVault(me.email);
    } catch {
      showAuth();
    }
  }

  init();
})();
