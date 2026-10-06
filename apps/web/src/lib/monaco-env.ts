'use client';

import loader from '@monaco-editor/loader';

let configured = false;

/**
 * Configure Monaco loader to resolve all scripts and assets locally from the
 * web server origin (e.g. http://10.216.0.155/monaco-editor/0.55.1/vs) so
 * the editor runs completely offline/air-gapped with zero external CDN calls.
 */
export function initMonacoEnv() {
  if (typeof window === 'undefined' || configured) return;
  loader.config({
    paths: {
      vs: `${window.location.origin}/monaco-editor/0.55.1/vs`,
    },
  });
  configured = true;
}

if (typeof window !== 'undefined') {
  initMonacoEnv();
}
