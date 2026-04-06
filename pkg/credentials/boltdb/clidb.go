// Package boltdb provides a persistent credentials.ClientCredStore that keeps data in a file.
package boltdb

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"math"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
	_ "golang.org/x/crypto/blake2s"

	"code.kerpass.org/golang/pkg/credentials"
)

const (
	connectTimeout = 5 * time.Second
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

		// create db buckets
		for _, bucketname := range []string{"cardTbl", "cardTknIdx", "cardRlmIdx", "realmTbl", "realmIdx"} {
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

// CreateCard saves card in the cliCredStore.
// It errors if the card could not be saved.
func (self cliCredStore) CreateCard(card *credentials.Card) error {
	err := card.Check()
	if nil != err {
		return wrapError(err, "invalid card")
	}

	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return wrapError(err, "failed connecting to database")
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loadSchema")
		}

		// set realm
		// note that existing realm are updated each time a new card is added.
		var rlm credentials.Realm
		err = card.RealmExport(&rlm)
		if nil != err {
			return wrapError(err, "failed exporting Realm")
		}
		srzrlm, err := cbor.Marshal(rlm)
		if nil != err {
			return wrapError(err, "failed cbor.Marshal of Realm")
		}
		rId := sch.realmIdx.Get(rlm.RealmId)
		if nil == rId {
			if sch.realmTbl.Sequence() >= math.MaxInt {
				return wrapError(ErrSeqOverflow, "too many Realm")
			}
			uId, err := sch.realmTbl.NextSequence()
			if nil != err {
				return wrapError(err, "failed realmTbl.NextSequence")
			}
			rId = byteId(int(uId))
			err = sch.realmIdx.Put(rlm.RealmId, rId)
			if nil != err {
				return wrapError(err, "failed updating realmIdx")
			}
		}
		err = sch.realmTbl.Put(rId, srzrlm)
		if nil != err {
			return wrapError(err, "failed saving realm in realmTbl bucket")
		}

		// save new card
		// note that cards are "immutable"
		// existing cards are not changed
		var curcard credentials.ClientCard
		var found bool
		if card.ID > 0 {

			// card should be present in the store
			found, err = sch.loadCardById(card.ID, &curcard)
			if nil != err {
				return wrapError(err, "failed loading existing card")
			}
			if !found {
				return wrapError(ErrNotFound, "failed loading existing card")
			}

			// check that RealmId & IdToken are the same
			if (bytes.Compare(card.RealmId, curcard.RealmId) != 0) || (bytes.Compare(card.IdToken, curcard.IdToken) != 0) {
				return wrapError(
					credentials.ErrCardMutation,
					"forbidden operation, attend to change RealmId or IdToken of existing card",
				)
			}

			return nil // curcard left unchanged
		} else {
			// see if a card with same IdToken exists
			found, err := sch.loadCardByKey(card.IdToken, &curcard)
			if nil != err {
				return wrapError(err, "failed loading existing card")
			}
			if found {
				if bytes.Compare(card.RealmId, curcard.RealmId) != 0 {
					return wrapError(
						credentials.ErrCardMutation,
						"forbidden operation, attend to change RealmId of existing card",
					)
				}
				card.ID = curcard.ID

				return nil // curcard left unchanged
			}
		}

		// extract ClientCard
		err = card.ClientExport(&curcard)
		if nil != err {
			return wrapError(err, "failed exporting ClientCard")
		}

		// generates card ID
		if sch.cardTbl.Sequence() >= math.MaxInt {
			return wrapError(ErrValidation, "too many card")
		}
		nId, err := sch.cardTbl.NextSequence()
		if nil != err {
			return wrapError(err, "failed generating card ID")
		}
		curcard.ID = int(nId)
		card.ID = curcard.ID

		csk := cardStoreKeys{}
		readStoreKeys(&curcard, &csk)

		// store the ClientCard
		srzcard, err := cbor.Marshal(curcard)
		if nil != err {
			return wrapError(err, "failed cbor.Marshal of ClientCard")
		}
		err = sch.cardTbl.Put(csk.cardId, srzcard)
		if nil != err {
			return wrapError(err, "failed storing card in cardTbl bucket")
		}

		// add entry in cardRlmIdx
		err = sch.cardRlmIdx.Put(csk.realmKey, csk.cardId)
		if nil != err {
			return wrapError(err, "failed updating the cardRlmIdx bucket")
		}

		// add entry in cardTknIdx
		err = sch.cardTknIdx.Put(csk.tokenKey, csk.cardId)
		if nil != err {
			return wrapError(err, "failed updating the cardTknIdx bucket")
		}

		return nil
	})

	return err
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
		var card credentials.ClientCard

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		found, err := sch.loadCardById(cId, &card)
		if nil != err {
			return wrapError(err, "failed accessing existing card")
		}
		if !found {
			return nil
		}

		csk := cardStoreKeys{}
		card.ID = cId
		readStoreKeys(&card, &csk)

		err = sch.cardTbl.Delete(csk.cardId)
		if nil != err {
			// unlikely as cardTbl is writable
			return err
		}

		err = sch.cardRlmIdx.Delete(csk.realmKey)
		if nil != err {
			// unlikely as cardRlmIdx is writable
			return err
		}

		err = sch.cardTknIdx.Delete(csk.tokenKey)
		if nil != err {
			// unlikely as cardTknIdx is writable
			return err
		}

		removed = true

		return nil
	})

	return removed, err
}

// SetCardLabel assign a new label to the card with cId ID.
// It errors if the label could not be assigned.
func (self cliCredStore) SetCardLabel(cId int, lbl string) error {
	lbl = strings.TrimSpace(lbl)
	if "" == lbl {
		return wrapError(ErrValidation, "empty label")
	}

	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		var card credentials.ClientCard
		found, err := sch.loadCardById(cId, &card)
		if nil != err {
			return wrapError(err, "failed loading card")
		}
		if !found {
			return wrapError(ErrNotFound, "missing card")
		}
		card.ID = cId
		card.Label = lbl
		srzcard, err := cbor.Marshal(card)
		if nil != err {
			return wrapError(err, "failed cbor.Marshal of ClientCard")
		}
		err = sch.cardTbl.Put(byteId(cId), srzcard)
		if nil != err {
			return wrapError(err, "failed storing card in cardTbl bucket")
		}

		return nil

	})

	return err
}

// LoadCard copies ClientCard with ID cId into dst.
// It errors if the ClientCard could not be copied.
func (self cliCredStore) LoadCard(cId int, dst *credentials.ClientCard) error {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		found, err := sch.loadCardById(cId, dst)
		if nil != err {
			return wrapError(err, "failed loading card")
		}
		if !found {
			return wrapError(ErrNotFound, "missing card")
		}

		return nil
	})

	return err
}

// LoadInfo copies CardInfo for card with cId ID into dst.
// It errors the CardInfo could not be copied.
func (self cliCredStore) LoadInfo(cId int, dst *credentials.CardInfo) error {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		card := credentials.ClientCard{}
		found, err := sch.loadCardById(cId, &card)
		if nil != err {
			return wrapError(err, "failed loading card")
		}
		if !found {
			return wrapError(ErrNotFound, "missing card")
		}

		realm := credentials.Realm{}
		realmCache := make(map[int]credentials.Realm)
		rId, err := sch.loadRealmByKey(card.RealmId, realmCache, &realm)
		if nil != err {
			return wrapError(err, "failed loading realm")
		}

		dst.ID = cId
		dst.RealmID = rId
		dst.AppName = realm.AppName
		dst.AppDesc = realm.AppDesc
		dst.Label = card.Label

		return nil

	})

	return err
}

// LoadRealm copies the Realm keyed by rId into dst.
// It errors if the Realm could not be copied
func (self cliCredStore) LoadRealm(rId int, dst *credentials.Realm) error {
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		var err error

		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		srzrlm := sch.realmTbl.Get(byteId(rId))
		if nil == srzrlm {
			return wrapError(ErrNotFound, "missing realm")
		}
		err = cbor.Unmarshal(srzrlm, dst)

		return wrapError(err, "failed unmarshaling realm") // nil if err is nil
	})

	return err
}

// ListInfo returns a list of CardInfo that matches qry.
func (self cliCredStore) ListInfo(qry credentials.CardQuery) ([]credentials.CardInfo, error) {
	err := qry.Check()
	if nil != err {
		return nil, wrapError(err, "failed qry.Check")
	}
	db, err := bolt.Open(self.dbpath, 0600, &bolt.Options{Timeout: connectTimeout})
	if nil != err {
		return nil, wrapError(err, "failed connecting to the database")
	}
	defer db.Close()

	rk := rangeKeys{}
	readRangeKeys(qry, &rk)

	var infos []credentials.CardInfo
	err = db.View(func(tx *bolt.Tx) error {
		sch, err := loadSchema(tx)
		if nil != err {
			return wrapError(err, "failed loading schema")
		}

		rlmCache := make(map[int]credentials.Realm)

		var srzcard []byte
		var c *bolt.Cursor
		var isRealmKey bool
		var uId uint64
		if len(qry.RealmId) > 0 {
			c = sch.cardRlmIdx.Cursor()
			isRealmKey = true
		} else {
			c = sch.cardTbl.Cursor()
			isRealmKey = false
		}
		for k, v := c.Seek(rk.minKey); k != nil && bytes.Compare(k, rk.maxKey) <= 0; k, v = c.Next() {
			if qry.Limit > 0 && len(infos) >= qry.Limit {
				break
			}
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

			// load card
			card := credentials.ClientCard{}
			err = cbor.Unmarshal(srzcard, &card)
			if nil != err {
				return wrapError(err, "failed unmarshaling card")
			}
			if uId > math.MaxInt {
				return wrapError(ErrValidation, "Invalid ClientCard.ID")
			} else {
				card.ID = int(uId)
			}

			// load card Realm
			realm := credentials.Realm{}
			rId, err := sch.loadRealmByKey(card.RealmId, rlmCache, &realm)
			if nil != err {
				return wrapError(err, "failed retrieving card realm")
			}

			// join card & realm into info
			info := credentials.CardInfo{
				ID:      card.ID,
				RealmID: rId,
				AppName: realm.AppName,
				AppDesc: realm.AppDesc,
				Label:   card.Label,
			}

			infos = append(infos, info)
		}

		return nil

	})

	return infos, err
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
	cardTbl    *bolt.Bucket
	cardTknIdx *bolt.Bucket
	cardRlmIdx *bolt.Bucket
	realmTbl   *bolt.Bucket
	realmIdx   *bolt.Bucket
}

func loadSchema(tx *bolt.Tx) (schema, error) {
	rv := schema{
		cardTbl:    tx.Bucket([]byte("cardTbl")),
		cardTknIdx: tx.Bucket([]byte("cardTknIdx")),
		cardRlmIdx: tx.Bucket([]byte("cardRlmIdx")),
		realmTbl:   tx.Bucket([]byte("realmTbl")),
		realmIdx:   tx.Bucket([]byte("realmIdx")),
	}
	var err error
	if nil == rv.cardTbl || nil == rv.cardTknIdx || nil == rv.cardRlmIdx || nil == rv.realmTbl || nil == rv.realmIdx {
		err = newError("1 or more bucket is missing")
	}

	return rv, err
}

func (self schema) loadCardById(cId int, dst *credentials.ClientCard) (bool, error) {
	srzcard := self.cardTbl.Get(byteId(cId))
	if nil == srzcard {
		return false, nil
	}

	err := cbor.Unmarshal(srzcard, dst)
	if nil != err {
		return false, wrapError(err, "failed unmarshalling ClientCard")
	}
	dst.ID = cId

	return true, nil
}

func (self schema) loadCardByKey(idtoken []byte, dst *credentials.ClientCard) (bool, error) {
	srzId := self.cardTknIdx.Get(hash(idtoken))
	if nil == srzId {
		return false, nil
	}
	srzcard := self.cardTbl.Get(srzId)
	if nil == srzcard {
		return false, wrapError(ErrNotFound, "missing ClientCard")
	}

	err := cbor.Unmarshal(srzcard, dst)
	if nil != err {
		return false, wrapError(err, "failed unmarshalling ClientCard")
	}
	cId := binary.BigEndian.Uint64(srzId)
	if cId > math.MaxInt {
		return false, wrapError(ErrValidation, "cId > math.MaxInt")
	}
	dst.ID = int(cId)

	return true, nil
}

// loadRealmByKey resolves realmid to a Realm, writing the result into dst.
// It looks up realmid in realmCache first, then falls back to self.realmTbl.
// Realms loaded from realmTbl are added to realmCache for subsequent calls.
// It returns the integer ID of the Realm, which can be passed to LoadRealm.
func (self schema) loadRealmByKey(realmid []byte, realmCache map[int]credentials.Realm, dst *credentials.Realm) (int, error) {
	var rId int
	srzId := self.realmIdx.Get(realmid)
	if nil == srzId {
		return rId, wrapError(ErrNotFound, "invalid realm RealmId")
	}
	uid := binary.BigEndian.Uint64(srzId)
	if uid > math.MaxInt {
		return rId, wrapError(ErrValidation, "invalid srzId")
	}
	rId = int(uid)
	realm, found := realmCache[rId]
	if found {
		*dst = realm
		return rId, nil
	}
	srzrlm := self.realmTbl.Get(srzId)
	if nil == srzrlm {
		return rId, wrapError(ErrNotFound, "missing srzrlm")
	}
	err := cbor.Unmarshal(srzrlm, &realm)
	if nil != err {
		return rId, wrapError(err, "failed unmarshaling realm")
	}
	realmCache[rId] = realm
	*dst = realm

	return rId, nil

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
	// 8 bytes BigEndian encoding of card.ID.
	// key serialized ClientCard in cardTbl bucket.
	cardId []byte

	// composite key [RealmId | cardId]
	// key cardId in cardRlmIdx bucket.
	realmKey []byte

	// hash of card IdToken
	// key cardId in cardTknIdx bucket.
	tokenKey []byte
}

func readStoreKeys(card *credentials.ClientCard, dst *cardStoreKeys) {
	// cardId
	dst.cardId = byteId(card.ID)

	// realmKey
	rsz := len(card.RealmId)
	rk := make([]byte, rsz+8)
	copy(rk, card.RealmId)
	copy(rk[rsz:], dst.cardId)
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
	// qry.MinId is int, hence (uint64(qry.MinId) + 1) does not wrap to 0
	binary.BigEndian.PutUint64(minkey[psz:], uint64(qry.MinId)+1)
	dst.minKey = minkey

	// maxKey
	maxkey := make([]byte, psz+8)
	copy(maxkey, qry.RealmId)
	binary.BigEndian.PutUint64(maxkey[psz:], 0xFFFF_FFFF_FFFF_FFFF)
	dst.maxKey = maxkey
}
