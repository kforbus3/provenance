-- Host.Sudo's description understated its reach.
--
-- It said "connect as a login-only (no-sudo) account", which reads as though the
-- permission only chooses an account for interactive sessions. It now also governs
-- the ad-hoc command runner (which downgrades to the login-only account without it)
-- and is required IN ADDITION to their own permission by the paths that run as root
-- with no unprivileged mode: Ansible playbook runs, applying OpenSCAP remediation,
-- and support-bundle collection.
--
-- Description only. The grants are deliberately untouched: Host.Sudo remains seeded
-- to Administrator and Operator (see 0007_host_sudo.sql), so no existing deployment
-- loses access on upgrade. Removing it from Operator is an operator decision — it
-- takes away root on every host an operator can reach, which some deployments rely
-- on. See docs/security-guide.md §5.
UPDATE permissions
SET description = 'Root (sudo) on managed hosts: terminal, SFTP, and ad-hoc commands run as the privileged account instead of the login-only one, and it is additionally required to run playbooks, apply remediation, or collect support bundles'
WHERE key = 'Host.Sudo';
