-- Lilith schema upgrade 3 -> 4: receiver API keys
--
-- receiver_apikeys holds the bearer keys accepted by mojo_lilith_receiver.
-- Only the SHA-256 of each key is stored (key_sha256, base64) so a database
-- leak does not expose usable credentials; the key itself is shown once at
-- creation. allowed_ips and allowed_instances optionally scope a key: a push
-- is accepted only when the client IP is contained by one of allowed_ips
-- (host or subnet) and the pushed row's instance matches one of
-- allowed_instances. A NULL/empty array on either column means "no
-- restriction on that axis". allowed_instances entries may use the '*' and
-- '?' shell-style wildcards, e.g. 'foo-*'.

CREATE TABLE receiver_apikeys (
    id bigserial NOT NULL,
    name varchar(255) NOT NULL UNIQUE,
    key_sha256 varchar(44) NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT TRUE,
    allowed_ips cidr[],
    allowed_instances varchar(255)[],
    description varchar(2048),
    last_used TIMESTAMP WITH TIME ZONE,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    PRIMARY KEY(id)
);
