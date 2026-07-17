-- Lilith schema upgrade 5 -> 6: saved dashboard layouts
--
-- dashboards holds named web dashboard layouts. 'layout' is the JSON list of
-- widget placements (id/x/y/w/h) the Gridstack UI serializes. The web UI is
-- unauthenticated, so boards are global rather than per-user; the 'default'
-- board is created here and flagged is_default.

CREATE TABLE dashboards (
    id bigserial NOT NULL,
    name varchar(255) NOT NULL UNIQUE,
    layout jsonb NOT NULL DEFAULT '[]',
    is_default boolean NOT NULL DEFAULT FALSE,
    updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);

INSERT INTO dashboards (name, layout, is_default) VALUES ('default', '[]', TRUE);
