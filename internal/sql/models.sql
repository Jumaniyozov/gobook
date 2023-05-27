create table users
(
    id         serial
        constraint users_pk
            primary key,
    email      varchar(255) not null
        unique,
    first_name varchar(255) not null,
    last_name  varchar(255) not null,
    password   varchar(60)  not null,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now()
);

alter table users
    owner to postgres;

create table tokens
(
    id         serial
        constraint tokens_pk
            primary key,
    user_id    integer
        constraint tokens_users_id_fk
            references users,
    email      varchar(255)             not null,
    token      varchar(255)             not null,
    token_hash bytea                    not null,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now(),
    expiry     timestamp with time zone not null
);

alter table tokens
    owner to postgres;

