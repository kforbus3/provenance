-- Building an image is not the same act as rolling one out.
--
-- 0079 gave Imaging.Manage both, which conflated two things that separate
-- cleanly in practice. Building produces an artefact and consumes a lot of disk
-- and CPU; it changes nothing on any managed host, and the person who does it is
-- often the person who maintains the image rather than the person who runs the
-- fleet. Rolling out is the act that changes what a machine boots.
--
-- Splitting them is what makes "you may prepare the release, someone else
-- approves putting it on the fleet" expressible at all. Granting one has never
-- implied the other since a build reaches no host, so the split takes nothing
-- away that was load-bearing.

INSERT INTO permissions(key, description) VALUES
    ('Imaging.Build', 'Build OS images, update bundles and the netboot imager, and manage the artefact library')
ON CONFLICT (key) DO NOTHING;

-- Everyone who has Imaging.Manage today was already able to build, so granting
-- Build to exactly those roles is what keeps this migration a split rather than
-- a revocation somebody discovers when a build stops working.
INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Imaging.Build' FROM roles r
WHERE r.name IN ('Administrator', 'Operator')
ON CONFLICT DO NOTHING;

-- Reword Manage now that it no longer covers building.
UPDATE permissions
   SET description = 'Run staged rollouts, pair and hold machines, and install updates on hosts'
 WHERE key = 'Imaging.Manage';

-- And the provisioning stack: starting the PXE server, editing its network
-- configuration and assigning MACs to hostnames. Separate again, because it is
-- the one part of this that reconfigures a network segment, and the blast
-- radius of a wrong DHCP range is every machine on that switch.
INSERT INTO permissions(key, description) VALUES
    ('Imaging.Provision', 'Configure and run the PXE provisioning stack and MAC-to-hostname assignments')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Imaging.Provision' FROM roles r
WHERE r.name IN ('Administrator')
ON CONFLICT DO NOTHING;
