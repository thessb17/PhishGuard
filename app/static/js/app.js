/* PhishGuard - shared UI behaviour (CSP-safe: no inline script anywhere). */
(function () {
  "use strict";

  /** Read a JSON data block rendered by the server. */
  function readJSON(id) {
    var node = document.getElementById(id);
    if (!node) return null;
    try {
      return JSON.parse(node.textContent);
    } catch (err) {
      console.error("PhishGuard: could not parse data block", id, err);
      return null;
    }
  }
  window.PhishGuard = window.PhishGuard || {};
  window.PhishGuard.readJSON = readJSON;

  document.addEventListener("DOMContentLoaded", function () {
    /* Mobile sidebar toggle */
    var toggle = document.querySelector("[data-nav-toggle]");
    var shell = document.querySelector(".pg-shell");
    var sidebar = document.querySelector(".pg-sidebar");
    if (toggle && sidebar && shell) {
      toggle.addEventListener("click", function () {
        sidebar.classList.toggle("open");
        shell.classList.toggle("nav-open");
      });
      shell.addEventListener("click", function (event) {
        if (shell.classList.contains("nav-open") && !sidebar.contains(event.target) &&
            !toggle.contains(event.target)) {
          sidebar.classList.remove("open");
          shell.classList.remove("nav-open");
        }
      });
    }

    /* Copy-to-clipboard buttons */
    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        var value = button.getAttribute("data-copy");
        var done = function () {
          var original = button.innerHTML;
          button.innerHTML = '<i class="bi bi-check2"></i> Copied';
          setTimeout(function () { button.innerHTML = original; }, 1600);
        };
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(value).then(done).catch(function () {});
        } else {
          var area = document.createElement("textarea");
          area.value = value;
          area.style.position = "fixed";
          area.style.opacity = "0";
          document.body.appendChild(area);
          area.select();
          try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
          document.body.removeChild(area);
        }
      });
    });

    /* Fill a form field from a sample button */
    document.querySelectorAll("[data-fill-target]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = document.querySelector(button.getAttribute("data-fill-target"));
        if (target) {
          target.value = button.getAttribute("data-fill-value") || "";
          target.focus();
        }
      });
    });

    /* Confirmation prompts for destructive actions */
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.getAttribute("data-confirm"))) {
          event.preventDefault();
        }
      });
    });

    /* Select-all checkbox for participant pickers */
    document.querySelectorAll("[data-check-all]").forEach(function (master) {
      master.addEventListener("change", function () {
        var scope = document.querySelector(master.getAttribute("data-check-all"));
        if (!scope) return;
        scope.querySelectorAll('input[type="checkbox"]').forEach(function (box) {
          box.checked = master.checked;
        });
      });
    });

    /* Table quick filter */
    document.querySelectorAll("[data-filter-table]").forEach(function (input) {
      input.addEventListener("input", function () {
        var table = document.querySelector(input.getAttribute("data-filter-table"));
        if (!table) return;
        var needle = input.value.toLowerCase();
        table.querySelectorAll("tbody tr").forEach(function (row) {
          row.style.display = row.textContent.toLowerCase().indexOf(needle) === -1 ? "none" : "";
        });
      });
    });

    /* Auto-dismiss flash messages */
    document.querySelectorAll("[data-autodismiss]").forEach(function (node) {
      setTimeout(function () {
        node.style.transition = "opacity .4s";
        node.style.opacity = "0";
        setTimeout(function () { node.remove(); }, 420);
      }, 7000);
    });
  });
})();

/* ---------------------------------------------------------------------------
 * CSRF helper for JavaScript-initiated unsafe requests.
 *
 * The UI is form-based today, so nothing here is called yet. It exists so the
 * first script that needs to POST uses the supported Flask-WTF mechanism -
 * the meta tag plus an X-CSRFToken header - instead of inventing something.
 * The token is never logged.
 * ------------------------------------------------------------------------ */
(function () {
  function csrfToken() {
    var el = document.querySelector('meta[name="csrf-token"]');
    return el ? el.getAttribute("content") : "";
  }

  // fetch() wrapper that attaches the token to unsafe, same-origin requests.
  window.pgFetch = function (url, options) {
    options = options || {};
    var method = (options.method || "GET").toUpperCase();
    if (["POST", "PUT", "PATCH", "DELETE"].indexOf(method) !== -1) {
      options.headers = Object.assign({}, options.headers, {
        "X-CSRFToken": csrfToken()
      });
      options.credentials = options.credentials || "same-origin";
    }
    return fetch(url, options);
  };
})();
