import React from "react";
import { Button } from "./ui";

// A render error in one page must not blank the whole app. Navigation resets the
// boundary (Root keys it by route). After a deploy, an open tab can ask for a
// script chunk that no longer exists; that gets its own, clearer message.
export default class ErrorBoundary extends React.Component {
  state = { error: null };
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error) { console.error("[ui] render error:", error && error.message); }
  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const stale = /ChunkLoadError|Loading chunk|dynamically imported module/i.test(`${error.name} ${error.message}`);
    return (
      <div className="page">
        <div className="state error">
          <div className="t">{stale ? "TFII was updated" : "This page hit a problem"}</div>
          <div className="d">{stale ? "A newer version was deployed while this tab was open. Reload to continue."
            : "The rest of the app is fine. Try again, or go back."}</div>
          <div className="row" style={{ gap: 8, marginTop: 8, justifyContent: "center" }}>
            {!stale && <Button size="sm" onClick={() => this.setState({ error: null })}>Try again</Button>}
            <Button size="sm" variant={stale ? "primary" : undefined} onClick={() => window.location.reload()}>Reload</Button>
          </div>
        </div>
      </div>
    );
  }
}
