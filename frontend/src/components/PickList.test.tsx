import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { PickList } from "./PickList";

const HOSTS = [
  { value: "ai", label: "ai" },
  { value: "docker", label: "docker" },
  { value: "coreswitch", label: "coreswitch" },
  { value: "containers", label: "containers" },
];

describe("PickList", () => {
  // The whole point: typing narrows the list, so picking one host out of nineteen
  // does not mean scrolling a menu.
  it("narrows the options as you type", async () => {
    render(<PickList label="Host" value="" onChange={() => {}} options={HOSTS} anyLabel="All hosts" />);
    const input = screen.getByLabelText("Host");
    // focus THEN change. A mouseDown opens the list but swallows the typing, which
    // is why this is worth stating: the same sequence in the other order silently
    // tests an unfiltered list.
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "cont" } });

    expect(await screen.findByText("containers")).toBeInTheDocument();
    expect(screen.queryByText("docker")).not.toBeInTheDocument();
  });

  // Type, press Enter, done — without reaching for the arrow keys. That is what
  // autoHighlight buys, and it is the difference between fast and merely possible.
  it("selects the top match on Enter", async () => {
    const onChange = vi.fn();
    render(<PickList label="Host" value="" onChange={onChange} options={HOSTS} anyLabel="All hosts" />);
    const input = screen.getByLabelText("Host");

    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: "core" } });
    await screen.findByText("coreswitch");
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onChange).toHaveBeenCalledWith("coreswitch");
  });

  // Clearing the field is how you go back to "no filter", and it must report an
  // empty value rather than leaving the previous host selected.
  it("reports an empty value when cleared", async () => {
    const onChange = vi.fn();
    render(<PickList label="Host" value="docker" onChange={onChange} options={HOSTS} anyLabel="All hosts" />);
    expect(screen.getByLabelText("Host")).toHaveValue("docker");

    fireEvent.click(screen.getByTitle("Clear"));
    expect(onChange).toHaveBeenCalledWith("");
  });

  // The unselected state has to SAY what it means. "Host" alone does not tell you
  // that leaving it empty searches every host.
  it("says what the empty state means", () => {
    render(<PickList label="Host" value="" onChange={() => {}} options={HOSTS} anyLabel="All hosts" />);
    expect(screen.getByLabelText("Host")).toHaveAttribute("placeholder", "All hosts");
  });

  // A saved filter naming a host that has since been removed must still show what
  // it says. Blanking it silently would read as "no filter", which is a different
  // search than the one the person asked for.
  it("keeps showing a value that is no longer in the options", () => {
    render(<PickList label="Host" value="retired-host" onChange={() => {}}
      options={[...HOSTS, { value: "retired-host", label: "retired-host" }]} />);
    expect(screen.getByLabelText("Host")).toHaveValue("retired-host");
  });
});
