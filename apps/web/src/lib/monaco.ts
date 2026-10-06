/**
 * Shared Monaco editor loader configuration — single source of truth for how
 * the Monaco editor assets are located and initialized across the app.
 *
 * WHY THIS EXISTS
 * --------------
 * @monaco-editor/react loads the actual Monaco runtime
 * (loader.js, editor/editor.main.*, worker bundles, CSS) from a CDN
 * (https://cdn.jsdelivr.net) when no paths are configured. That works in a
 * normal browser with internet access but silently fails in closed /
 * air-gapped / restricted-network deployments:
 *
 *   - the CDN is unreachable (no internet, WAF/Proxy/DNS block)
 *   - a Content-Security-Policy blocks remote script sources
 *   - a browser extension blocks the network request
 *
 * In every one of those cases the injected <script> fires a DOM `error`
 * event, the loader rejects, and @monaco-editor/react logs
 * `Monaco initialization: error: { type: 'error', target: script }`
 * while leaving the editor in a permanently frozen state.
 *
 * FIX: point @monaco-editor/loader at locally bundled assets with
 * `paths.vs = '/monaco/vs'`. Those files ship under `apps/web/public/monaco/`
 * and are served same-origin by the Next.js static middleware — zero external
 * network calls. This is the ground-truth fix for the closed-network case.
 *
 * See SafeCodeEditor.tsx for the second line of defense: if the Monaco
 * runtime still cannot mount (e.g. memory pressure on a low-end browser), the
 * component degrades to a fully functional <textarea>.
 */

import loader from '@monaco-editor/loader';

/** Serve Monaco from the project's bundled static assets, not a remote CDN. */
loader.config({
  paths: {
    vs: '/monaco/vs',
  },
});

export default loader;
