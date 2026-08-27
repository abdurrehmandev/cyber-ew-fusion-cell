// Ensure window.fetch setter compatibility in sandboxed iframe environments
try {
  let origFetch = window.fetch;
  const desc = Object.getOwnPropertyDescriptor(window, "fetch") ||
               Object.getOwnPropertyDescriptor(Object.getPrototypeOf(window), "fetch") ||
               (typeof Window !== "undefined" && Object.getOwnPropertyDescriptor(Window.prototype, "fetch"));
  if (!desc || !desc.set) {
    try {
      Object.defineProperty(window, "fetch", {
        configurable: true,
        enumerable: true,
        get: () => origFetch,
        set: (v) => { origFetch = v; },
      });
    } catch {
      // ignore
    }
  }
} catch {
  // ignore
}

import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
