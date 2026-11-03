import React from "react";
import ReactDOM from "react-dom/client";
import "./theme-boot";
import "@fontsource-variable/ibm-plex-sans/wght.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import App from "./App";
import "./styles.css";
import "./app-layout.css";
import "./shell.css";
import "./workbench.css";
import "./ledger.css";
import { installNativeContextMenuGuard } from "./native-context-menu";







installNativeContextMenuGuard();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
