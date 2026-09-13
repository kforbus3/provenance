-- Backfills `declared` for rows written before 0094 added the column.
--
-- 0094 defaults it to false, which is what every row was before the column
-- existed. But the rows that matter are the ones ALREADY in that state: a tag a
-- compose file names, checked and recorded, with no container running it. On the
-- release that adds the column those all read false, so the screen drops them --
-- and the operator upgrades specifically to see them, looks, and finds nothing.
--
-- The same shape as a new collector inheriting an old gate's timestamp: the
-- feature is correct and invisible on exactly the release that introduces it,
-- until something unrelated happens to refresh the data.
--
-- A row qualifies when nothing runs that repository:tag, something DOES run the
-- repository at some other tag, and the tag carries a digit. The last condition
-- keeps a moving tag like :latest -- left behind after its container moved to a
-- pinned version -- from being relabelled as a compose declaration; those are
-- pruned by the next check pass anyway.
UPDATE container_image_updates u
SET declared = true
WHERE u.declared = false
  AND u.tag ~ '[0-9]'
  AND NOT EXISTS (
        SELECT 1 FROM host_inventory hi,
             LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
        WHERE c->>'repository' = u.repository AND c->>'tag' = u.tag)
  AND EXISTS (
        SELECT 1 FROM host_inventory hi,
             LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
        WHERE c->>'repository' = u.repository);
