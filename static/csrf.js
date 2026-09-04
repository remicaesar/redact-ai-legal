// Attaches the CSRF token to state-changing requests.
//
// Wrapping fetch once, here, rather than editing every call site: there are
// ~30 of them across the templates, and the failure mode of missing one is a
// button that silently stops working. A wrapper cannot be forgotten by the
// next fetch someone adds.
//
// Loaded before the page's own scripts so their first request is already
// covered.
(function () {
  "use strict";

  var SAFE_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1, TRACE: 1 };

  function token() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function isSameOrigin(url) {
    try {
      // Relative URLs resolve against the document, so they are same-origin by
      // construction. Absolute ones are compared explicitly -- the token must
      // never be attached to a request leaving this origin.
      return new URL(url, window.location.href).origin === window.location.origin;
    } catch (err) {
      return false;
    }
  }

  var original = window.fetch;
  if (typeof original !== "function") {
    return;
  }

  window.fetch = function (input, init) {
    var options = init || {};
    var method = (options.method || (input && input.method) || "GET").toUpperCase();
    var url = typeof input === "string" ? input : input && input.url;

    if (SAFE_METHODS[method] || !url || !isSameOrigin(url)) {
      return original.call(this, input, options);
    }

    // Headers can arrive as a Headers instance, an array of pairs, or a plain
    // object; normalising through Headers handles all three without clobbering
    // what the caller set.
    var headers = new Headers(options.headers || (input && input.headers) || {});
    if (!headers.has("X-CSRF-Token")) {
      headers.set("X-CSRF-Token", token());
    }

    var merged = {};
    for (var key in options) {
      if (Object.prototype.hasOwnProperty.call(options, key)) {
        merged[key] = options[key];
      }
    }
    merged.headers = headers;
    return original.call(this, input, merged);
  };
})();
