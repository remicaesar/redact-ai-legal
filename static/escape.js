// Shared HTML escaping for the server-rendered templates.
//
// This helper used to be redefined in each of index.html, matters.html,
// matter.html, studio.html and audit.html as a text node whose innerHTML was
// read back. That escapes &, < and > but NOT quotes -- quote escaping only
// happens when the browser serializes an *attribute* value, not a text node.
// Every copy was also interpolated into double-quoted attributes (for example
// title="${escapeHtml(doc.filename)}"), fed by values that are unvalidated
// free text (a stored filename, a reviewer's replacement_text), so a value
// containing a quote could close the attribute early. There is one
// implementation now and it escapes all five characters.
//
// Values that end up inside an inline event-handler string (onclick="...")
// need this AND must never be reachable from free-text user input -- prefer a
// data-* attribute plus a delegated listener there instead (see #reviewGroups
// and #findingGroups in studio.html).
function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// escapeAttr was the attribute-safe variant back when escapeHtml was not.
// Kept as an alias so existing attribute call sites keep reading as attribute
// escaping at the point of use.
const escapeAttr = escapeHtml;
