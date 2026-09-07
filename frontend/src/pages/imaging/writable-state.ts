// The writable-state values and their validation, kept out of the component file
// so fast refresh keeps working there — and so the path rule can be tested.

export interface WritableStateValue {
  stateModel: string;
  slotPrivateUpper: boolean;
  persistPaths: string;
  slotPrivatePaths: string;
  volatilePaths: string;
  resetPaths: string;
  keepPaths: string;
  ownPaths: string;
}

export const WRITABLE_STATE_DEFAULT: WritableStateValue = {
  stateModel: "overlay",
  slotPrivateUpper: false,
  persistPaths: "",
  slotPrivatePaths: "",
  volatilePaths: "",
  resetPaths: "",
  keepPaths: "",
  ownPaths: "",
};

// A path directive only means anything if it is absolute — the builder silently
// skips anything else, so a typo would be a directive that appears to have been
// accepted and is not in the image. Said here instead.
export function invalidPaths(value: string): string[] {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .filter((p) => !p.startsWith("/"));
}
