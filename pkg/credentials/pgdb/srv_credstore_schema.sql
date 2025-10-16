create extension if not exists moddatetime;

set role kp_trust;

begin;

  create schema if not exists kerpass;

  create table if not exists timestamp_mixin (
    created_at timestamptz not null default current_timestamp,

    changed_at timestamptz not null default current_timestamp
  );

  create table if not exists kerpass.realm (
    id bytea not null primary key
      check(octet_length(id) >= 32),

    app_name varchar(64) not null,

    app_logo bytea
      check(octet_length(app_logo) <= 65536),

    like timestamp_mixin including all
  );

  create table if not exists kerpass."authorization" (

    id bytea not null primary key
      check(octet_length(id) >= 32),

    realm_id bytea not null references kerpass.realm(id)
      on delete cascade,

    like timestamp_mixin including all

  );

  create table if not exists kerpass.card (

    id bytea not null primary key
      check(octet_length(id) >= 32),

    realm_id bytea not null references kerpass.realm(id)
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
      foreach tablename in array array['realm', 'authorization', 'card']
      loop
	begin
	  execute format(
	    $stmt$
	    create trigger trg_modified_at before update on kerpass.%i
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

commit;
