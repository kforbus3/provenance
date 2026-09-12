import { Component, type ReactNode } from "react";
import { Alert, AlertTitle, Button } from "@mui/material";

// A crash in one panel must not blank the page.
//
// It did: an image whose hosts had all moved on came back with `hosts: null`,
// one `.filter` threw, and React unmounted the entire app — a white screen with
// nothing on it, on a page that was working a moment earlier. The underlying
// null is fixed, but "one bad field takes the whole screen" is the part worth
// removing, because the next one will be a different field.
//
// A class component because that is the only thing React gives an error boundary.
export class TabErrorBoundary extends Component<
  { children: ReactNode; name: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Alert
        severity="error"
        action={
          <Button color="inherit" size="small" onClick={() => this.setState({ error: null })}>
            Retry
          </Button>
        }
      >
        <AlertTitle>{this.props.name} could not be displayed</AlertTitle>
        {/* The message, because "something went wrong" is not a bug report and the
            person reading this is the one who can send us a useful one. */}
        {this.state.error.message}
      </Alert>
    );
  }
}
