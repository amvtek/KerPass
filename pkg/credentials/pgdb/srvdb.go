package pgdb

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"code.kerpass.org/golang/pkg/credentials"
)

const pgdriver = "pgx"

// PGDB is implemented by pgx.Tx, pgx.Conn & pgxpool.Pool
// accessing a postgres database through this common interface simplifies testing
type PGDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ServerCredStore struct {
	DB          PGDB
	cardAdapter *credentials.SrvCardStorageAdapter
}

//go:embed srv_credstore_schema.sql
var schemaScriptTpl string

func ServerCredStoreMigrate(pgconn *pgx.Conn, dbschema string) error {

	// render schema creation script
	schemaName := pgx.Identifier{dbschema}.Sanitize()
	schemaOwner := pgx.Identifier{fmt.Sprintf("%s_owner", dbschema)}.Sanitize()
	schemaScript := strings.ReplaceAll(schemaScriptTpl, "${schema_name}", schemaName)
	schemaScript = strings.ReplaceAll(schemaScript, "${schema_owner}", schemaOwner)

	_, err := pgconn.Exec(context.Background(), schemaScript)

	return wrapError(err, "Failed db schema initialization") // nil if err is nil...

}

func NewServerCredStore(ctx context.Context, dsn string) (*ServerCredStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if nil != err {
		return nil, wrapError(err, "failed connection pool creation")
	}

	return &ServerCredStore{DB: pool}, nil

}

// ListRealm lists the Realm in the ServerCredStore.
// It errors if the ServerCredStore is not reachable.
func (self *ServerCredStore) ListRealm(ctx context.Context) ([]credentials.Realm, error) {
	rows, err := self.DB.Query(
		ctx,
		// columns are renamed to match credentials.Realm struct
		`SELECT
		   id as "RealmId",
		   app_name as "AppName",
		   app_logo as "AppLogo"
		 FROM
		   realm
		`,
	)
	if nil != err {
		return nil, wrapError(err, "failed DB.Query")
	}
	realms, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[credentials.Realm])
	return realms, wrapError(err, "failed pgx.CollectRows") // nil if err is nil
}

// LoadRealm loads realm data for realmId into dst.
// It errors if realm data were not successfully loaded.
func (self *ServerCredStore) LoadRealm(ctx context.Context, realmId []byte, dst *credentials.Realm) error {
	rows, err := self.DB.Query(
		ctx,
		`SELECT
		   id as "RealmId",
		   app_name as "AppName",
		   app_logo as "AppLogo"
		 FROM
		   realm
		 WHERE
		   id = $1
		`,
		realmId,
	)
	if nil != err {
		return wrapError(err, "failed db.Query")
	}
	realm, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByNameLax[credentials.Realm])
	if nil != err {
		if errors.Is(err, pgx.ErrNoRows) {
			return wrapError(credentials.ErrNotFound, "unknown realm")
		}
		return wrapError(err, "failed loading realm")
	}
	*dst = realm
	return nil

}

// SaveRealm saves realm into the ServerCredStore.
// It errors if realm could not be saved.
func (self *ServerCredStore) SaveRealm(ctx context.Context, realm credentials.Realm) error {
	err := realm.Check()
	if nil != err {
		return wrapError(err, "invalid realm")
	}
	_, err = self.DB.Exec(
		ctx,
		`INSERT INTO realm(id, app_name, app_logo) VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET
		 app_name = EXCLUDED.app_name,
		 app_logo = EXCLUDED.app_logo`,
		realm.RealmId,
		realm.AppName,
		realm.AppLogo,
	)

	return wrapError(err, "failed saving realm") // nil if err is nil...
}

// RemoveRealm removes the Realm with realmId identifier from the ServerCredStore.
// It errors if the ServerCredStore is not reachable or if realmId does not exists.
func (self *ServerCredStore) RemoveRealm(ctx context.Context, realmId []byte) error {
	var deleted int
	row := self.DB.QueryRow(
		ctx,
		`WITH deleted AS (DELETE FROM realm WHERE id = $1 RETURNING id)
		 SELECT count(id) FROM deleted`,
		realmId,
	)
	err := row.Scan(&deleted)
	if nil != err {
		return wrapError(err, "failed DELETE query")
	}
	if 0 == deleted {
		return wrapError(credentials.ErrNotFound, "unknown realmId")
	}

	return nil
}

// PopEnrollAuthorization loads authorization data in ea and remove it from the ServerCredStore.
// It returns an error if the authorization could not be loaded and removed.
func (self *ServerCredStore) PopEnrollAuthorization(ctx context.Context, authorizationId []byte, ea *credentials.EnrollAuthorization) error {
	row := self.DB.QueryRow(
		ctx,
		`DELETE FROM enroll_authorization a
		 USING "realm" r WHERE a.id = $1 AND a.realm_id = r.id
		 RETURNING a.id, a.realm_id, r.app_name, r.app_logo`,
		authorizationId,
	)
	err := row.Scan(&ea.AuthorizationId, &ea.RealmId, &ea.AppName, &ea.AppLogo)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return wrapError(credentials.ErrNotFound, "failed loading authorization")
		}
		return wrapError(err, "failed loading authorization")
	}
	return nil
}

// SaveEnrollAuthorization saves ea in the ServerCredStore.
// It errors if the authorization could not be saved.
func (self *ServerCredStore) SaveEnrollAuthorization(ctx context.Context, ea credentials.EnrollAuthorization) error {
	_, err := self.DB.Exec(
		ctx,
		`INSERT INTO enroll_authorization(realm_id, id)
		 VALUES ($1, $2)
		 ON CONFLICT(id) DO NOTHING`,
		ea.RealmId,
		ea.AuthorizationId,
	)
	if nil != err {
		return wrapError(err, "Failed saving authorization")
	}
	return nil
}

// AuthorizationCount returns the number of EnrollAuthorization in the ServerCredStore.
func (self *ServerCredStore) AuthorizationCount(ctx context.Context) (int, error) {
	var rv int
	row := self.DB.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM enroll_authorization`,
	)
	err := row.Scan(&rv)
	if nil != err {
		return 0, wrapError(err, "failed count query")
	}

	return rv, nil
}

// LoadCard loads stored card data in dst.
// It returns true if card data were successfully loaded.
func (self *ServerCredStore) LoadCard(ctx context.Context, cardId []byte, dst *credentials.ServerCard) error {

	// load related SrvStoreCard
	sId, err := self.cardAdapter.GetStorageId(cardId)
	if nil != err {
		return wrapError(credentials.ErrNotFound, "failed storage id determination")
	}
	var sc credentials.SrvStoreCard
	row := self.DB.QueryRow(
		ctx,
		`SELECT id, realm_id, seal_type, key_data
		 FROM card
		 WHERE id = $1`,
		sId,
	)
	err = row.Scan(&sc.ID, &sc.RealmId, &sc.SealType, &sc.KeyData)
	if nil != err {
		if errors.Is(err, pgx.ErrNoRows) {
			return wrapError(credentials.ErrNotFound, "failed loading card")
		}
		return wrapError(err, "failed loading card")
	}

	// adapt retrieved SrvStoreCard to ServerCard
	err = self.cardAdapter.FromStorage(cardId, sc, dst)
	if nil != err {
		return wrapError(err, "failed card adaptation")
	}

	return nil
}

// SaveCard saves card in the ServerCredStore.
// It errors if the card could not be saved.
func (self *ServerCredStore) SaveCard(ctx context.Context, card credentials.ServerCard) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "Invalid card")
	}

	// transform card in SrvStoreCard
	var sc credentials.SrvStoreCard
	err = self.cardAdapter.ToStorage(card.CardId, card, &sc)
	if nil != err {
		return wrapError(err, "Failed SrvStoreCard adaptation")
	}

	_, err = self.DB.Exec(
		ctx,
		`INSERT INTO card(realm_id, id, seal_type, key_data)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO UPDATE SET
		 seal_type = excluded.seal_type,
		 key_data = excluded.key_data
		`,
		sc.RealmId,
		sc.ID,
		sc.SealType,
		sc.KeyData,
	)
	if nil != err {
		return wrapError(err, "Failed saving card")
	}
	return nil
}

// RemoveCard removes the ServerCard with cardId identifier from the ServerCredStore.
// It returns true if the ServerCard was effectively removed.
func (self *ServerCredStore) RemoveCard(ctx context.Context, cardId []byte) bool {
	var deleted int
	row := self.DB.QueryRow(
		ctx,
		`WITH deleted AS (DELETE FROM card WHERE id = $1 RETURNING id)
		 SELECT count(id) FROM deleted`,
		cardId,
	)
	err := row.Scan(&deleted)
	if nil != err || 0 == deleted {
		return false
	}

	return true
}

// CountCard returns the number of ServerCard in the ServerCredStore.
func (self *ServerCredStore) CardCount(ctx context.Context) (int, error) {
	var rv int
	row := self.DB.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM card`,
	)
	err := row.Scan(&rv)
	if nil != err {
		return 0, wrapError(err, "failed count query")
	}

	return rv, nil
}

var _ credentials.ServerCredStore = &ServerCredStore{}
