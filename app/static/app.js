const routes = {
  login: "/static/login.html",
  dashboard: "/static/dashboard.html",
  orders: "/static/orders.html",
  profile: "/static/profile.html",
  graphqlLab: "/static/graphql-lab.html",
};

const graphqlScenarios = {
  vulnerable: {
    sensitiveMe: {
      label: "Exposição de dados",
      query: `query SensitiveMe {
  me {
    id
    name
    email
    role
    isAdmin
    passwordHash
    internalNotes
    accountStatus
  }
}`,
    },
    bolaOrder: {
      label: "BOLA order(id: 3)",
      query: `query ReadOtherUserOrder {
  order(id: 3) {
    id
    product
    status
    shippingAddress
    userId
    user {
      id
      name
      email
    }
  }
}`,
    },
    adminUsers: {
      label: "Users sem admin",
      query: `query ListUsersWithoutAdmin {
  users {
    id
    name
    email
    role
    isAdmin
    passwordHash
  }
}`,
    },
    massAssignment: {
      label: "Mass assignment",
      query: `mutation PromoteCurrentUser {
  updateMe(input: {
    name: "André"
    email: "andre@example.com"
    role: "admin"
    isAdmin: true
    internalNotes: "Promovido via GraphQL vulnerável"
  }) {
    id
    name
    email
    role
    isAdmin
    internalNotes
  }
}`,
    },
    recursiveQuery: {
      label: "Query recursiva",
      query: `query RecursiveUserOrders {
  me {
    id
    name
    orders {
      id
      product
      user {
        id
        name
        orders {
          id
          product
        }
      }
    }
  }
}`,
    },
  },
  secure: {
    safeMe: {
      label: "Perfil seguro",
      query: `query SafeMe {
  me {
    id
    name
    email
  }
}`,
    },
    blockedSensitiveField: {
      label: "Campo sensível bloqueado",
      query: `query BlockedSensitiveField {
  me {
    id
    name
    passwordHash
  }
}`,
    },
    blockedBola: {
      label: "BOLA bloqueado",
      query: `query BlockedOrder {
  order(id: 3) {
    id
    product
    shippingAddress
    userId
  }
}`,
    },
    blockedAdminUsers: {
      label: "Admin bloqueado",
      query: `query BlockedAdminUsers {
  adminUsers {
    id
    name
    email
    role
  }
}`,
    },
    safeUpdate: {
      label: "Update permitido",
      query: `mutation SafeUpdate {
  updateMe(input: {
    name: "André"
    email: "andre@example.com"
  }) {
    id
    name
    email
  }
}`,
    },
    invalidLimit: {
      label: "Limite inválido",
      query: `query InvalidLimit {
  myOrders(limit: 50) {
    id
    product
  }
}`,
    },
    introspectionBlocked: {
      label: "Introspection bloqueada",
      query: `query IntrospectionBlocked {
  __schema {
    queryType {
      name
    }
  }
}`,
    },
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindLogout();

  const page = document.body.dataset.page;
  if (page !== "login") {
    requireSession();
  }

  if (page === "login") initLogin();
  if (page === "dashboard") initDashboard();
  if (page === "orders") initOrders();
  if (page === "order-detail") initOrderDetail();
  if (page === "profile") initProfile();
  if (page === "graphql-lab") initGraphqlLab();
});

function getToken() {
  return localStorage.getItem("access_token");
}

function setToken(token) {
  localStorage.setItem("access_token", token);
}

function clearToken() {
  localStorage.removeItem("access_token");
}

function requireSession() {
  if (!getToken()) {
    window.location.href = routes.login;
  }
}

function bindLogout() {
  document.querySelectorAll("[data-action='logout']").forEach((button) => {
    button.addEventListener("click", () => {
      clearToken();
      window.location.href = routes.login;
    });
  });
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (getToken()) {
    headers.set("Authorization", `Bearer ${getToken()}`);
  }

  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;

  if (response.status === 401 && document.body.dataset.page !== "login") {
    clearToken();
    window.location.href = routes.login;
    return null;
  }

  if (!response.ok) {
    const message = data?.detail || "Não foi possível concluir o pedido.";
    throw new Error(Array.isArray(message) ? message[0]?.msg : message);
  }

  return data;
}

function initLogin() {
  const form = document.querySelector("#login-form");
  const errorBox = document.querySelector("#login-error");

  if (getToken()) {
    window.location.href = routes.dashboard;
    return;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.textContent = "";

    const payload = {
      email: form.email.value.trim(),
      password: form.password.value,
    };

    try {
      const data = await apiFetch("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setToken(data.access_token);
      window.location.href = routes.dashboard;
    } catch (error) {
      errorBox.textContent = error.message;
    }
  });
}

async function initDashboard() {
  try {
    const [user, orders] = await Promise.all([
      apiFetch("/api/vulnerable/me"),
      apiFetch("/api/vulnerable/orders"),
    ]);
    renderUser(user);
    renderDashboardStats(orders);
    renderRecentOrders(orders);
  } catch (error) {
    showPageError(error.message);
  }
}

async function initOrders() {
  try {
    const orders = await apiFetch("/api/vulnerable/orders");
    renderOrdersTable(orders);
    bindOrderSearch(orders);
  } catch (error) {
    showPageError(error.message);
  }
}

async function initOrderDetail() {
  const params = new URLSearchParams(window.location.search);
  const orderId = params.get("id");
  const errorBox = document.querySelector("#order-detail-error");

  if (!orderId) {
    errorBox.textContent = "Encomenda não encontrada.";
    return;
  }

  try {
    const order = await apiFetch(`/api/vulnerable/orders/${encodeURIComponent(orderId)}`);
    renderOrderDetail(order);
  } catch (error) {
    errorBox.textContent = error.message;
  }
}

async function initProfile() {
  const form = document.querySelector("#profile-form");
  const message = document.querySelector("#profile-message");

  try {
    const user = await apiFetch("/api/vulnerable/me");
    form.name.value = user.name;
    form.email.value = user.email;
  } catch (error) {
    message.classList.add("error");
    message.textContent = error.message;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.classList.remove("error");
    message.textContent = "";

    const payload = {
      name: form.name.value.trim(),
      email: form.email.value.trim(),
    };

    try {
      const user = await apiFetch("/api/vulnerable/me", {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      renderUser(user);
      message.textContent = "Perfil atualizado.";
    } catch (error) {
      message.classList.add("error");
      message.textContent = error.message;
    }
  });
}

function initGraphqlLab() {
  const form = document.querySelector("#graphql-form");
  const endpointSelect = document.querySelector("#graphql-endpoint");
  const scenarioSelect = document.querySelector("#graphql-scenario");
  const queryEditor = document.querySelector("#graphql-query");
  const responsePanel = document.querySelector("#graphql-response");
  const endpointLabel = document.querySelector("#graphql-url");
  const message = document.querySelector("#graphql-message");

  function syncScenarioOptions() {
    const endpoint = endpointSelect.value;
    const scenarios = graphqlScenarios[endpoint];
    scenarioSelect.innerHTML = Object.entries(scenarios)
      .map(
        ([value, scenario]) =>
          `<option value="${value}">${escapeHtml(scenario.label)}</option>`
      )
      .join("");
    queryEditor.value = Object.values(scenarios)[0].query;
    endpointLabel.textContent = `/graphql/${endpoint}`;
    responsePanel.textContent = "{}";
    message.textContent = "";
  }

  endpointSelect.addEventListener("change", syncScenarioOptions);
  scenarioSelect.addEventListener("change", () => {
    const scenario = graphqlScenarios[endpointSelect.value][scenarioSelect.value];
    queryEditor.value = scenario.query;
    message.textContent = "";
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const endpoint = endpointSelect.value;
    const url = `/graphql/${endpoint}`;
    endpointLabel.textContent = url;
    message.classList.remove("error");
    message.textContent = "A executar...";

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getToken()}`,
        },
        body: JSON.stringify({ query: queryEditor.value }),
      });
      const text = await response.text();
      const data = text ? JSON.parse(text) : null;
      responsePanel.textContent = JSON.stringify(data, null, 2);
      message.textContent = response.ok ? "Pedido concluído." : "Pedido rejeitado.";
    } catch (error) {
      message.classList.add("error");
      message.textContent = error.message;
      responsePanel.textContent = "{}";
    }
  });

  syncScenarioOptions();
}

function renderUser(user) {
  document.querySelectorAll("[data-user-name]").forEach((element) => {
    element.textContent = user.name;
  });
  document.querySelectorAll("[data-user-email]").forEach((element) => {
    element.textContent = user.email;
  });
}

function renderDashboardStats(orders) {
  const total = orders.reduce((sum, order) => sum + Number(order.price), 0);
  const active = orders.filter((order) => !isDone(order.status)).length;

  document.querySelector("#stat-orders").textContent = orders.length;
  document.querySelector("#stat-total").textContent = formatCurrency(total);
  document.querySelector("#stat-active").textContent = active;
}

function renderRecentOrders(orders) {
  const container = document.querySelector("#recent-orders");
  const recentOrders = orders.slice(0, 3);

  container.innerHTML = recentOrders
    .map(
      (order) => `
        <article class="order-card">
          <span class="status-badge ${statusClass(order.status)}">${escapeHtml(order.status)}</span>
          <h3>${escapeHtml(order.product)}</h3>
          <div class="order-meta">
            <span>#${order.id}</span>
            <strong>${formatCurrency(order.price)}</strong>
          </div>
          <a class="row-link" href="/static/order-detail.html?id=${order.id}">Ver detalhe</a>
        </article>
      `
    )
    .join("");
}

function renderOrdersTable(orders) {
  const table = document.querySelector("#orders-table");
  const empty = document.querySelector("#orders-empty");

  empty.hidden = orders.length > 0;
  table.innerHTML = orders
    .map(
      (order) => `
        <tr>
          <td>#${order.id}</td>
          <td>${escapeHtml(order.product)}</td>
          <td><span class="status-badge ${statusClass(order.status)}">${escapeHtml(order.status)}</span></td>
          <td>${formatCurrency(order.price)}</td>
          <td><a class="row-link" href="/static/order-detail.html?id=${order.id}">Abrir</a></td>
        </tr>
      `
    )
    .join("");
}

function bindOrderSearch(orders) {
  const search = document.querySelector("#order-search");
  search.addEventListener("input", () => {
    const query = search.value.trim().toLowerCase();
    const filtered = orders.filter((order) => {
      return `${order.product} ${order.status}`.toLowerCase().includes(query);
    });
    renderOrdersTable(filtered);
  });
}

function renderOrderDetail(order) {
  document.querySelector("#order-title").textContent = `Encomenda #${order.id}`;
  document.querySelector("#order-detail").innerHTML = `
    <div class="detail-block">
      <div class="detail-line">
        <span>Produto</span>
        <strong>${escapeHtml(order.product)}</strong>
      </div>
      <div class="detail-line">
        <span>Estado</span>
        <strong><span class="status-badge ${statusClass(order.status)}">${escapeHtml(order.status)}</span></strong>
      </div>
      <div class="detail-line">
        <span>Valor</span>
        <strong>${formatCurrency(order.price)}</strong>
      </div>
    </div>
    <div class="detail-block">
      <div class="detail-line">
        <span>Morada de entrega</span>
        <strong>${escapeHtml(order.shipping_address)}</strong>
      </div>
      <div class="detail-line">
        <span>Referência</span>
        <strong>IS-${String(order.id).padStart(5, "0")}</strong>
      </div>
    </div>
  `;
}

function statusClass(status) {
  const normalized = status.toLowerCase();
  if (normalized.includes("entregue")) return "done";
  if (normalized.includes("transporte")) return "transit";
  if (normalized.includes("enviado")) return "sent";
  return "";
}

function isDone(status) {
  return status.toLowerCase().includes("entregue");
}

function formatCurrency(value) {
  return new Intl.NumberFormat("pt-PT", {
    style: "currency",
    currency: "EUR",
  }).format(value);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showPageError(message) {
  const main = document.querySelector("main");
  const error = document.createElement("p");
  error.className = "form-message error";
  error.textContent = message;
  main.prepend(error);
}
