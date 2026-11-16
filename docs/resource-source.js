let loader = null;
const listeners = new Set();

export const getResourceLoader = () => loader;

export function setResourceLoader(fn) {
  loader = typeof fn === "function" ? fn : null;
  for (const l of listeners) l(loader);
}

export function onResourceLoaderChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
