import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { StackEditor } from "./StacksPage";

// This dialog sent {hostId, name, compose, note} and no path.
//
// That absence was not neutral. The server read it as "no location given" and
// filled in /opt/stacks/<name>, which moved media-stack off the directory it was
// adopted from. The next rollout created the new directory, wrote the compose
// file into it, and ran `docker compose` somewhere with no .env beside it — so
// the operator was told their compose file was invalid ("WIREGUARD_PRIVATE_KEY
// is missing a value") when the file on the host was fine.
//
// A save that changes only the text must not change where the stack lives.

vi.mock("../api/stacks", async () => {
  const actual = await vi.importActual<typeof import("../api/stacks")>("../api/stacks");
  return { ...actual, saveStack: vi.fn() };
});
import { saveStack, type ContainerStack } from "../api/stacks";

const adopted: ContainerStack = {
  id: "s1",
  hostId: "h1",
  hostname: "docker",
  name: "media-stack",
  compose: "services:\n  web:\n    image: nginx:1.27\n",
  path: "/home/keith/media-stack",
  revision: 4,
  enabled: true,
  createdAt: "2026-09-12T00:00:00Z",
  updatedAt: "2026-09-12T00:00:00Z",
};

// The dialog fills its fields when it is opened ON a stack — the page mounts it
// closed and swaps the stack in — so the test opens it the same way.
function renderEditor(stack: ContainerStack) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const props = {
    open: true,
    hosts: [{ id: "h1", hostname: "docker" }],
    onClose: () => {},
    onSaved: () => {},
  };
  const { rerender } = render(
    <QueryClientProvider client={qc}><StackEditor {...props} stack={null} /></QueryClientProvider>,
  );
  rerender(
    <QueryClientProvider client={qc}><StackEditor {...props} stack={stack} /></QueryClientProvider>,
  );
}

describe("StackEditor", () => {
  beforeEach(() => vi.clearAllMocks());

  it("keeps a stack where it is when only the compose text is edited", async () => {
    vi.mocked(saveStack).mockResolvedValue({ ...adopted, revision: 5 });
    renderEditor(adopted);

    fireEvent.change(screen.getByLabelText(/docker-compose\.yml/i), {
      target: { value: "services:\n  web:\n    image: nginx:1.30\n" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => expect(saveStack).toHaveBeenCalled());
    expect(vi.mocked(saveStack).mock.calls[0][0]).toMatchObject({
      hostId: "h1",
      name: "media-stack",
      path: "/home/keith/media-stack",
    });
  });

  it("shows the operator where the stack is deployed", () => {
    // A path that is never displayed is a path nobody can notice is wrong.
    renderEditor(adopted);
    expect(screen.getByDisplayValue("/home/keith/media-stack")).toBeInTheDocument();
  });

  it("sends a path the operator actually changed", async () => {
    vi.mocked(saveStack).mockResolvedValue({ ...adopted, path: "/srv/media-stack" });
    renderEditor(adopted);

    fireEvent.change(screen.getByLabelText(/directory on the host/i), {
      target: { value: "/srv/media-stack" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => expect(saveStack).toHaveBeenCalled());
    expect(vi.mocked(saveStack).mock.calls[0][0].path).toBe("/srv/media-stack");
  });
});
