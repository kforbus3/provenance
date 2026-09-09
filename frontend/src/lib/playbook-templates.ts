// Starter playbooks offered when creating a new one.
//
// A blank editor is the right default for someone who knows Ansible and has a
// specific job in mind. It is the wrong one for the job this deployment does
// most: installing an A/B update. That playbook is not hard, but it is easy to
// get subtly wrong -- the running slot must not be touched, a reboot is a
// separate decision from the install, and a machine that comes back on the slot
// it started on has FAILED rather than succeeded, because that is GRUB falling
// back to a slot whose replacement would not boot. Shipping it as a template
// puts those decisions in front of whoever starts from it, instead of leaving
// them to be rediscovered on a machine.
//
// The content is JSON-encoded rather than written as a template literal because
// the playbook contains backticks and backslashes, both of which a template
// literal would eat. The readable copy is deploy/playbooks/ab-update.yml; this
// is generated from it and a test asserts the two are identical, because two
// copies of a playbook that drift apart are worse than either alone.

export interface PlaybookTemplate {
  id: string;
  label: string;
  description: string;
  name: string;
  playbookDescription: string;
  content: string;
}

export const PLAYBOOK_TEMPLATES: PlaybookTemplate[] = [
  {
    id: "blank",
    label: "Example",
    description: "A minimal playbook to start from.",
    name: "",
    playbookDescription: "",
    content: "---\n- name: Example playbook\n  hosts: all\n  become: true\n  tasks:\n    - name: Ensure the system is up to date\n      ansible.builtin.package:\n        name: \"*\"\n        state: latest\n",
  },
  {
    id: "ab-update",
    label: "A/B update (RAUC)",
    description:
      "Install a RAUC bundle into the inactive slot on A/B machines, with an "
      + "optional reboot and a check that the new slot actually came up.",
    name: "A/B update",
    playbookDescription: "Install a RAUC bundle into the inactive slot on A/B machines",
    content: "---\n# Install an A/B (RAUC) update on machines that Blackfriars manages as hosts.\n#\n# This is the same operation a rollout performs, driven from the Playbooks page\n# instead. Use it when you want to update hosts directly \u2014 a handful of machines,\n# an out-of-band fix, or a host that has no machine record \u2014 and use a rollout\n# when you want the safety rails that come with one: canary, soak, batching, a\n# failure budget and a maintenance window. Nothing here reproduces those.\n#\n# Variables (set them under \"Extra variables\" when you run this):\n#\n#   bundle_url    Bundle to install. Leave unset and each machine asks the server\n#                 it was imaged from for the newest one, which is what a bare\n#                 `ab-update` does. Set it to pin every host to one bundle.\n#   reboot_after  false by default. The update is written to the *inactive* slot\n#                 and nothing changes until a reboot, so installing is safe at\n#                 any hour and switching over is a separate decision.\n#   reboot_timeout  How long to wait for a machine to come back (seconds).\n#\n# What makes this safe: the running slot is never written. If the new slot fails\n# to boot, GRUB's try-counter falls back to the slot that is running now. The\n# worst case for a bad bundle is a reboot, not a lost machine.\n\n- name: Install an A/B update\n  hosts: all\n  become: true\n  gather_facts: true\n\n  vars:\n    bundle_url: \"\"\n    reboot_after: false\n    reboot_timeout: 600\n\n  tasks:\n    # Fail on the machines that cannot take an update before touching any of\n    # them, rather than discovering it host by host midway through a batch.\n    - name: Check that this is an A/B machine\n      ansible.builtin.stat:\n        path: /usr/local/sbin/ab-update\n      register: ab_update_bin\n\n    - name: Refuse hosts that have no A/B layout\n      ansible.builtin.fail:\n        msg: >-\n          {{ inventory_hostname }} has no /usr/local/sbin/ab-update, so it is not\n          an A/B machine and cannot take a RAUC bundle. Remove it from the target\n          list; nothing on it has been changed.\n      when: not ab_update_bin.stat.exists\n\n    - name: Record the slot that is running now\n      ansible.builtin.command: cat /proc/cmdline\n      register: cmdline_before\n      changed_when: false\n\n    # default([], true) before first(), not just default() after it. A cmdline\n    # with no rauc.slot makes regex_search return None, and default() replaces\n    # undefined values rather than None \u2014 so first() was handed None and the play\n    # died with \"'NoneType' object is not iterable\" instead of reporting the\n    # 'unknown' this was written to report.\n    - name: Extract the running slot\n      ansible.builtin.set_fact:\n        slot_before: \"{{ cmdline_before.stdout | regex_search('rauc\\\\.slot=([AB])', '\\\\1') | default([], true) | first | default('unknown') }}\"\n\n    - name: Show what will be updated\n      ansible.builtin.debug:\n        msg: >-\n          {{ inventory_hostname }} is running slot {{ slot_before }};\n          the update will be written to the other one\n          {{ '(bundle: ' ~ bundle_url ~ ')' if bundle_url else '(newest bundle from its imaging server)' }}.\n\n    # The long one. Streaming a bundle over HTTP and verifying it takes minutes\n    # on a slow link, and ab-update falls back to downloading it first if\n    # streaming fails, so the timeout has to allow for both.\n    #\n    # changed_when is deliberate: ab-update exits non-zero on every failure, so\n    # reaching here at all means the inactive slot was written.\n    - name: Install the bundle into the inactive slot\n      ansible.builtin.command: >-\n        /usr/local/sbin/ab-update {{ bundle_url | quote if bundle_url else '' }}\n      register: update_result\n      changed_when: update_result.rc == 0\n      timeout: 3600\n\n    - name: Show what the machine reported\n      ansible.builtin.debug:\n        var: update_result.stdout_lines\n\n    # Everything below only runs when you asked for it. An installed update that\n    # has not been rebooted into is a perfectly good end state.\n    - name: Reboot into the updated slot\n      ansible.builtin.reboot:\n        reboot_timeout: \"{{ reboot_timeout }}\"\n        msg: \"Rebooting into the updated A/B slot (Blackfriars)\"\n      when: reboot_after | bool\n\n    - name: Read the slot that came up\n      ansible.builtin.command: cat /proc/cmdline\n      register: cmdline_after\n      changed_when: false\n      when: reboot_after | bool\n\n    - name: Extract the running slot\n      ansible.builtin.set_fact:\n        slot_after: \"{{ cmdline_after.stdout | regex_search('rauc\\\\.slot=([AB])', '\\\\1') | default([], true) | first | default('unknown') }}\"\n      when: reboot_after | bool\n\n    # A machine that came back on the slot it started on did not fail to reboot \u2014\n    # it booted the new slot, that slot did not come up, and GRUB fell back. That\n    # is the safety net working, and it is the one outcome that must not be\n    # reported as success.\n    - name: Fail if the machine fell back to the old slot\n      ansible.builtin.fail:\n        msg: >-\n          {{ inventory_hostname }} rebooted but is running slot {{ slot_after }},\n          the same slot as before. The updated slot did not boot and GRUB fell\n          back. The machine is healthy and running its previous release; check\n          `journalctl -b -1` on it for why the new slot failed.\n      when:\n        - reboot_after | bool\n        - slot_after == slot_before\n        - slot_before != 'unknown'\n\n    - name: Report the running slot\n      ansible.builtin.debug:\n        msg: \"{{ inventory_hostname }} is now running slot {{ slot_after }} (was {{ slot_before }}).\"\n      when: reboot_after | bool\n",
  },
];
