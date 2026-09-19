import { Autocomplete, TextField } from "@mui/material";

export type PickOption = { value: string; label: string };

/**
 * A single-choice picker you can type into.
 *
 * Every list in Provenance backed by DATA rather than a fixed set of choices
 * grows: hosts, groups, images, bundles, credentials. A plain select over nineteen
 * hosts means opening a menu and hunting for a name, and it gets worse with every
 * machine added.
 *
 * Deliberately NOT for fixed enumerations (severity, protocol, day of week).
 * Typeahead over four values is slower than a menu, not faster — it adds a filter
 * step to a list you can already read in one glance.
 *
 * "No filter" is the EMPTY state, not an option in the list. Representing it as a
 * real option with an empty value means MUI keeps syncing the input back to that
 * option's label, which overwrites each character as it is typed — the field looks
 * like it is ignoring the keyboard. So empty means no selection, `anyLabel`
 * becomes the placeholder, and the clear button is how you get back to it.
 *
 * `autoHighlight` is what makes it quick: type three characters, press Enter, no
 * arrow keys. `openOnFocus` keeps it behaving like the select it replaces for
 * anyone who would rather click.
 */
export function PickList({
  label, value, onChange, options, anyLabel, sx, disabled, helperText, fullWidth,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: PickOption[];
  /** Placeholder for the unselected state, e.g. "All hosts". */
  anyLabel?: string;
  sx?: object;
  disabled?: boolean;
  helperText?: string;
  fullWidth?: boolean;
}) {
  // A value that is not in the list is still shown rather than blanked: a saved
  // filter naming a host that has since been removed should say so, because a
  // blank field reads as "no filter" and that is a different search.
  const selected =
    options.find((o) => o.value === value) ?? (value ? { value, label: value } : null);
  return (
    <Autocomplete
      size="small"
      sx={sx}
      fullWidth={fullWidth}
      disabled={disabled}
      options={options}
      value={selected}
      autoHighlight
      openOnFocus
      isOptionEqualToValue={(o, v) => o.value === v.value}
      getOptionLabel={(o) => o.label}
      onChange={(_, v) => onChange(v?.value ?? "")}
      renderInput={(p) => (
        <TextField {...p} label={label} placeholder={anyLabel} helperText={helperText} />
      )}
    />
  );
}
