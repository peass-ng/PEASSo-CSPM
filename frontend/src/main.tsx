import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App, ErrorBoundary } from "./App";
import "./styles.css";
import "./theme.css";
import "./Controls.css";
import { prewarmElk } from "./elkWorker";
// Parse the shared ELK layout worker before the first map is opened.
prewarmElk();
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 15000, refetchOnWindowFocus: false },
  },
});
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
);
