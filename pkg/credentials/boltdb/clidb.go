// Package boltdb provides a persistent credentials.ClientCredStore that keeps data in a file.
package boltdb

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
	_ "golang.org/x/crypto/blake2s"

	"code.kerpass.org/golang/pkg/credentials"
)

const (
	connectTimeout = 5 * time.Second
	maxCardId      = 0xFFFF_FFFF
	hashAlgo       = crypto.BLAKE2s_256
)

type cliCredStore struct {
	dbpath string
}

// New returns a ClientCredStore implementation that persists Cards in a single file boltdb database.
// It errors if the database schema can not be created.
func New(dbpath string) (credentials.ClientCredStore, error) {
	credStore := cliCredStore{dbpath: dbpath}

	db, err := bolt.Open(dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return nil, wrapError(err, "failed connecting to database")
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		var err error
		for _, bucketname := range []string{"cardTbl", "realmIdx", "tokenIdx"} {
			_, err = tx.CreateBucketIfNotExists([]byte(bucketname))
			if nil != err {
				return wrapError(err, "failed %s bucket creation", bucketname)
			}
		}

		return nil
	})
	if nil != err {
		return nil, wrapError(err, "failed db initialization")
	}

	return credStore, nil

}

// SaveCard saves card in the cliCredStore and returns the assigned ID.
// It errors if the card could not be saved.
func (self cliCredStore) SaveCard(card credentials.Card) (int, error) {
	err := card.Check()
	if nil != err {
		return 0, wrapError(err, "card is invalid")
	}

	// marshal card data using cbor
	srzcard, err := cbor.Marshal(card)
	if nil != err {
		return 0, wrapError(err, "failed cbor.Marshal(card)")
	}

	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return 0, wrapError(err, "failed connecting to database")
	}
	defer db.Close()

	var cId int // store assigned Card ID if any
	err = db.Update(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loadSchema")
		}

		var curcard credentials.Card
		var found bool
		if card.ID > 0 {

			// card should be present in the store
			found, err = sch.loadById(card.ID, &curcard)
			if nil != err {
				return wrapError(err, "failed loading existing card")
			}
			if !found {
				return newError("card has invalid ID, not in store")
			}

			// check that RealmId & IdToken are the same
			if (bytes.Compare(card.RealmId, curcard.RealmId) != 0) || (bytes.Compare(card.IdToken, curcard.IdToken) != 0) {
				return wrapError(
					credentials.ErrorCardMutation,
					"forbidden operation, attend to change RealmId or IdToken of existing card",
				)
			}
		} else {
			// see if a card with same IdToken exists
			found, err := sch.loadByToken(card.IdToken, &curcard)
			if nil != err {
				return wrapError(err, "failed loading existing card")
			}
			if found {
				if bytes.Compare(card.RealmId, curcard.RealmId) != 0 {
					return wrapError(
						credentials.ErrorCardMutation,
						"forbidden operation, attend to change RealmId of existing card",
					)
				}
				card.ID = curcard.ID
			} else {
				// generates card ID
				if sch.cardTbl.Sequence() >= maxCardId {
					return newError("too many card")
				}
				nId, err := sch.cardTbl.NextSequence()
				if nil != err {
					return wrapError(err, "failed generating card ID")
				}
				card.ID = int(nId)
			}
		}

		csk := cardStoreKeys{}
		readStoreKeys(card, &csk)

		// store the srzcard
		err = sch.cardTbl.Put(csk.cardKey, srzcard)
		if nil != err {
			return wrapError(err, "failed storing card in bucket")
		}

		// add entry in realmIdx
		err = sch.realmIdx.Put(csk.realmKey, csk.cardKey)
		if nil != err {
			return wrapError(err, "failed updating the realmIdx bucket")
		}

		// add entry in tokenIdx
		err = sch.tokenIdx.Put(csk.tokenKey, csk.cardKey)
		if nil != err {
			return wrapError(err, "failed updating the tokenIdx bucket")
		}

		cId = card.ID

		return nil
	})

	return cId, wrapError(err, "failed db.Update") // nil if err is nil
}

// RemoveCard removes the Card with cId ID from the cliCredStore.
// It returns true if the Card was effectively removed.
func (self cliCredStore) RemoveCard(cId int) (bool, error) {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return false, wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	var removed bool
	err = db.Update(func(tx *bolt.Tx) error {
		var err error
		var card credentials.Card

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		found, err := sch.loadById(cId, &card)
		if nil != err {
			return wrapError(err, "failed accessing existing card")
		}
		if !found {
			return nil
		}

		csk := cardStoreKeys{}
		readStoreKeys(card, &csk)

		err = sch.cardTbl.Delete(csk.cardKey)
		if nil != err {
			// unlikely as cardTbl is writable
			return err
		}

		err = sch.realmIdx.Delete(csk.realmKey)
		if nil != err {
			// unlikely as realmIdx is writable
			return err
		}

		err = sch.tokenIdx.Delete(csk.tokenKey)
		if nil != err {
			// unlikely as tokenIdx is writable
			return err
		}

		removed = true

		return nil
	})

	return removed, wrapError(err, "failed db.Update")
}

// LoadById loads the Card with ID cid into dst.
// It returns true if the Card was found and successfully loaded.
func (self cliCredStore) LoadById(cid int, dst *credentials.Card) (bool, error) {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return false, wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	var loaded bool
	err = db.View(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		found, err := sch.loadById(cid, dst)
		if nil != err {
			return wrapError(err, "failed loading card")
		}

		loaded = found

		return nil
	})

	return loaded, err
}

// ListInfo returns a list of CardInfo that matches qry.
func (self cliCredStore) ListInfo(qry credentials.CardQuery) ([]credentials.CardInfo, error) {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return nil, wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	rk := rangeKeys{}
	readRangeKeys(qry, &rk)

	// uses 16 as default qry.Limit
	if 0 == qry.Limit {
		qry.Limit = 16
	}

	cardlist := make([]credentials.CardInfo, 0, 4)
	err = db.View(func(tx *bolt.Tx) error {
		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		var srzcard []byte
		var c *bolt.Cursor
		var isRealmKey bool
		var uId uint64
		if len(qry.RealmId) > 0 {
			c = sch.realmIdx.Cursor()
			isRealmKey = true
		} else {
			c = sch.cardTbl.Cursor()
			isRealmKey = false
		}
		for k, v := c.Seek(rk.minKey); k != nil && bytes.Compare(k, rk.maxKey) <= 0 && len(cardlist) < qry.Limit; k, v = c.Next() {
			if isRealmKey {
				srzcard = sch.cardTbl.Get(v)
				uId = binary.BigEndian.Uint64(v)
			} else {
				srzcard = v
				uId = binary.BigEndian.Uint64(k)
			}
			if nil == srzcard {
				continue
			}
			card := credentials.CardInfo{}
			err = cbor.Unmarshal(srzcard, &card)
			if nil != err {
				return wrapError(err, "failed unmarshaling card")
			}
			if uId > math.MaxInt {
				return newError("Invalid Card.ID")
			} else {
				card.ID = int(uId)
			}
			cardlist = append(cardlist, card)
		}

		return nil

	})

	return cardlist, err
}

// Size returns the number of Card in the ClientCredStore.
func (self cliCredStore) CardCount() int {

	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return -1
	}
	defer db.Close()

	var count int
	err = db.View(func(tx *bolt.Tx) error {
		cardTbl := tx.Bucket([]byte("cardTbl"))
		if nil == cardTbl {
			return newError("missing cardTbl bucket")
		}
		stats := cardTbl.Stats()
		count = stats.KeyN

		return nil
	})

	if nil == err {
		return count
	}

	return -1
}

// schema holds cliCredStore buckets reference
type schema struct {
	cardTbl  *bolt.Bucket
	realmIdx *bolt.Bucket
	tokenIdx *bolt.Bucket
}

func loadSchema(tx *bolt.Tx) (schema, error) {
	rv := schema{
		cardTbl:  tx.Bucket([]byte("cardTbl")),
		realmIdx: tx.Bucket([]byte("realmIdx")),
		tokenIdx: tx.Bucket([]byte("tokenIdx")),
	}
	var err error
	if nil == rv.cardTbl || nil == rv.realmIdx || nil == rv.tokenIdx {
		err = newError("1 or more bucket is missing")
	}

	return rv, err
}

func (self schema) loadById(cId int, dst *credentials.Card) (bool, error) {
	srzcard := self.cardTbl.Get(byteId(cId))
	if nil == srzcard {
		return false, nil
	}

	err := cbor.Unmarshal(srzcard, dst)
	if nil == err {
		dst.ID = cId
	}

	return true, err
}

func (self schema) loadByToken(tok []byte, dst *credentials.Card) (bool, error) {
	cardId := self.tokenIdx.Get(hash(tok))
	srzcard := self.cardTbl.Get(cardId)
	if nil == srzcard {
		return false, nil
	}
	err := cbor.Unmarshal(srzcard, dst)
	if nil == err {
		cId := binary.BigEndian.Uint64(cardId)
		if cId > math.MaxInt {
			err = newError("invalid Card.ID")
		} else {
			dst.ID = int(cId)
		}
	}

	return true, err
}

// hash returns data digest
//
// digest is calculated using the hash function referenced by the hashAlgo constant
func hash(data []byte) []byte {
	if len(data) > 0 {
		h := hashAlgo.New()
		h.Write(data)
		return h.Sum(nil)
	}

	return nil
}

// cardStoreKeys holds keys used by the cliCredStore to store & index Card informations.
type cardStoreKeys struct {
	cardKey  []byte // key Card in cardTbl bucket
	realmKey []byte // key RealmId - Card in realmIdx bucket
	tokenKey []byte // key IdToken - Card in tokenIdx bucket
}

func readStoreKeys(card credentials.Card, dst *cardStoreKeys) {
	// cardKey
	dst.cardKey = byteId(card.ID)

	// realmKey
	rsz := len(card.RealmId)
	rk := make([]byte, rsz+8)
	copy(rk, card.RealmId)
	copy(rk[rsz:], dst.cardKey)
	dst.realmKey = rk

	// tokenKey
	// IdToken is hashed to preserve privacy
	dst.tokenKey = hash(card.IdToken)
}

// byteId returns 8 bytes BigEndian encoding of cid
func byteId(cid int) []byte {
	rv := make([]byte, 8)
	binary.BigEndian.PutUint64(rv, uint64(cid))

	return rv
}

type rangeKeys struct {
	minKey []byte
	maxKey []byte
}

func readRangeKeys(qry credentials.CardQuery, dst *rangeKeys) {
	psz := len(qry.RealmId)

	// minKey
	minkey := make([]byte, psz+8)
	copy(minkey, qry.RealmId)
	binary.BigEndian.PutUint64(minkey[psz:], uint64(qry.MinId))
	dst.minKey = minkey

	// maxKey
	maxkey := make([]byte, psz+8)
	copy(maxkey, qry.RealmId)
	binary.BigEndian.PutUint64(maxkey[psz:], 0xFFFF_FFFF_FFFF_FFFF)
	dst.maxKey = maxkey
}
