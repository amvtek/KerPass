-- this script shall be run by postgres super user

create extension if not exists moddatetime;


begin;

  -- create ${schema_owner} role if it does not exists
  do $$
    begin
      create role ${schema_owner};
    exception
      when duplicate_object then
	-- IGNORE
    end;
  $$;

  create schema if not exists ${schema_name} authorization ${schema_owner};
  set local role to ${schema_owner};
  set local search_path to ${schema_name}, public;

  create table if not exists timestamp_mixin (
    created_at timestamptz not null default current_timestamp,

    changed_at timestamptz not null default current_timestamp
  );

  create table if not exists realm (

    id serial not null primary key,

    rid bytea not null unique
      check(octet_length(rid) >= 32),

    app_name varchar(64) not null,

    app_desc varchar(255),

    app_logo bytea
      check(octet_length(app_logo) <= 65536),

    like timestamp_mixin including all
  );

  create table if not exists enroll_authorization (

    id serial not null primary key,

    aid bytea not null unique
      check(octet_length(aid) >= 32),

    realm_id integer not null references realm(id)
      on delete cascade,

    seal_type int not null default 0,

    user_data bytea,

    like timestamp_mixin including all

  );

  create table if not exists card (

    id serial not null primary key,

    cid bytea not null unique
      check(octet_length(cid) >= 32),

    realm_id integer not null references realm(id)
      on delete cascade,

    seal_type int not null default 0,

    key_data bytea not null,

    like timestamp_mixin including all

  );

  -- Add trigger that update the changed_at column each time a row is modified
  do $$
    declare
      tablename text;
    begin
      foreach tablename in array array['realm', 'enroll_authorization', 'card']
      loop
	begin
	  execute format(
	    $stmt$
	    create trigger trg_modified_at before update on %I
	      for each row execute procedure moddatetime(changed_at);
	    $stmt$,
	    tablename
	  );
	  raise notice 'trigger trg_modified_at added to table "%"', tablename;
	exception
	  when duplicate_object then
	    raise notice 'trigger trg_modified_at on "%" already exists, skipping', tablename;
	end;
      end loop;
    end;
  $$;

  drop table if exists timestamp_mixin;

commit;
