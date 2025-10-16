package boltdb

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"path"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"

	"code.kerpass.org/golang/pkg/credentials"
)

func TestNew(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	_, err := New(dbPath)
	if nil != err {
		t.Errorf("failed New, got error %v", err)
	}
}

func TestCardCreate(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	realmId := make([]byte, 32)
	rand.Read(realmId)
	card := credentials.Card{}
	for i := range 8 {
		err = initCard(&card)
		if nil != err {
			t.Fatalf("failed initCard #%d, got error %v", i, err)
		}
		card.RealmId = realmId
		_, err = store.SaveCard(card)
		if nil != err {
			t.Fatalf("failed SaveCard #%d, got error %v", i, err)
		}
	}

	if store.CardCount() != 8 {
		t.Errorf("failed CardCount control, %d != 8", store.CardCount())
	}

	err = printDB(t, dbPath)
	if nil != err {
		t.Errorf("failed printDB, got error %v", err)
	}

}

func TestCardCreateDelete01(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	// create 8 cards
	var cId int
	cards := make([]credentials.Card, 8)
	for i := range 8 {
		err = initCard(&cards[i])
		if nil != err {
			t.Fatalf("failed initCard #%d, got error %v", i, err)
		}
		cId, err = store.SaveCard(cards[i])
		if nil != err {
			t.Fatalf("failed SaveCard #%d, got error %v", i, err)
		}
		cards[i].ID = cId
	}

	// remove previous cards
	var removed bool
	for i, card := range cards {
		removed, err = store.RemoveCard(card.ID)
		if nil != err {
			t.Fatalf("failed RemoveCard #%d, got error %v", i, err)
		}
		if !removed {
			t.Fatalf("cards[%d] was not removed", i)
		}
	}

	if store.CardCount() != 0 {
		t.Errorf("failed CardCount control, %d != 0", store.CardCount())
	}

	err = printDB(t, dbPath)
	if nil != err {
		t.Errorf("failed printDB, got error %v", err)
	}

}

func TestCardCreateDelete02(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	// create 4 cards
	var cId int
	cards := make([]credentials.Card, 4)
	for i := range 4 {
		err = initCard(&cards[i])
		if nil != err {
			t.Fatalf("failed initCard #%d, got error %v", i, err)
		}
		cId, err = store.SaveCard(cards[i])
		if nil != err {
			t.Fatalf("failed SaveCard #%d, got error %v", i, err)
		}
		cards[i].ID = cId
	}

	// remove cards with even index
	var removed bool
	for i, card := range cards {
		if 0 == (i % 2) {
			removed, err = store.RemoveCard(card.ID)
			if nil != err {
				t.Fatalf("failed RemoveCard #%d, got error %v", i, err)
			}
			if !removed {
				t.Fatalf("cards[%d] was not removed", i)
			}
		}
	}

	if store.CardCount() != 2 {
		t.Errorf("failed CardCount control, %d != 2", store.CardCount())
	}

	err = printDB(t, dbPath)
	if nil != err {
		t.Errorf("failed printDB, got error %v", err)
	}

}

func TestLoadById(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	// create 32 cards
	var cId int
	cards := make([]credentials.Card, 32)
	for i := range 32 {
		err = initCard(&cards[i])
		if nil != err {
			t.Fatalf("failed initCard #%d, got error %v", i, err)
		}
		cId, err = store.SaveCard(cards[i])
		if nil != err {
			t.Fatalf("failed SaveCard #%d, got error %v", i, err)
		}
		cards[i].ID = cId
	}

	// keep cards {0, 7, 14, 21, 28}...
	var removed bool
	for i, card := range cards {
		if 0 != (i % 7) {
			removed, err = store.RemoveCard(card.ID)
			if nil != err {
				t.Fatalf("failed removing cards[%d], got error %v", i, err)
			}
			if !removed {
				t.Fatalf("cards[%d] was not removed", i)
			}
		}
	}

	var readcard credentials.Card
	var wasread bool
	for i, card := range cards {
		wasread, err = store.LoadById(card.ID, &readcard)
		if nil != err {
			t.Fatalf("failed loading card#%d, got error %v", card.ID, err)
		}
		if 0 == (i % 7) {
			if !wasread {
				t.Fatalf("card#%d could not be loaded", card.ID)
			}
			if !reflect.DeepEqual(card, readcard) {
				t.Fatalf("failed read card#%d control, \n%+v\n!=\n%+v", card.ID, card, readcard)
			}
		} else {
			if wasread {
				t.Fatalf("removed card#%d could be read", card.ID)
			}
		}
	}

	err = printDB(t, dbPath)
	if nil != err {
		t.Errorf("failed printDB, got error %v", err)
	}
}

func TestForbidMutation(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	// create 1 card
	card := credentials.Card{}
	err = initCard(&card)
	if nil != err {
		t.Fatalf("failed initCard, got error %v", err)
	}
	cId, err := store.SaveCard(card)
	if nil != err {
		t.Fatalf("failed SaveCard, got error %v", err)
	}
	card.ID = cId

	// attend to change RealmId through IdToken
	card1 := card
	card1.ID = 0
	realmId := make([]byte, len(card.RealmId))
	rand.Read(realmId)
	card1.RealmId = realmId
	_, err = store.SaveCard(card1)
	if !errors.Is(err, credentials.ErrCardMutation) {
		t.Error("store did not detect RealmId mutation")
	}

	// attend to change IdToken through ID
	card2 := card
	idToken := make([]byte, len(card.IdToken))
	rand.Read(idToken)
	card2.IdToken = idToken
	_, err = store.SaveCard(card2)
	if !errors.Is(err, credentials.ErrCardMutation) {
		t.Error("store did not detect IdToken mutation")
	}
}

func TestListInfo(t *testing.T) {
	tmpdir := t.TempDir()
	dbPath := path.Join(tmpdir, "card.db")
	store, err := New(dbPath)
	if nil != err {
		t.Fatalf("failed New, got error %v", err)
	}

	// create 2 distinct RealmId
	realms := [2][32]byte{}
	for i := range 2 {
		rand.Read(realms[i][:])
	}

	// create 32 cards
	var cId int
	cards := make([]credentials.Card, 32)
	for i := range 32 {
		err = initCard(&cards[i])
		if nil != err {
			t.Fatalf("failed initCard #%d, got error %v", i, err)
		}
		if 0 == (i % 8) {
			cards[i].RealmId = realms[0][:]
		} else {
			cards[i].RealmId = realms[1][:]
		}
		cId, err = store.SaveCard(cards[i])
		if nil != err {
			t.Fatalf("failed SaveCard #%d, got error %v", i, err)
		}
		cards[i].ID = cId
	}

	infos := make([]credentials.CardInfo, 0, 32)
	for _, card := range cards {
		infos = append(infos, card.Info())
	}

	// first query, ask for the first 8 CardInfo
	// bolt db keeps items in key order...
	qry1 := credentials.CardQuery{Limit: 8}
	res1, err := store.ListInfo(qry1)
	if nil != err {
		t.Fatalf("failed ListInfo(%v), got error %v", qry1, err)
	}
	if !reflect.DeepEqual(res1, infos[:8]) {
		t.Error("failed res1 control")
	}
	endId := res1[len(res1)-1].ID

	// second query, ask for the next 4 CardInfo
	qry2 := credentials.CardQuery{MinId: endId + 1, Limit: 4}
	res2, err := store.ListInfo(qry2)
	if nil != err {
		t.Fatalf("failed ListInfo(%v), got error %v", qry2, err)
	}
	if !reflect.DeepEqual(res2, infos[8:12]) {
		t.Error("failed res2 control")
	}

	// third query, ask for all CardInfo in realm r0
	r0 := realms[0][:]
	expect3 := []credentials.CardInfo{infos[0], infos[8], infos[16], infos[24]}
	qry3 := credentials.CardQuery{RealmId: r0, Limit: 255}
	res3, err := store.ListInfo(qry3)
	if nil != err {
		t.Fatalf("failed ListInfo(%v), got error %v", qry3, err)
	}
	if !reflect.DeepEqual(res3, expect3) {
		t.Error("failed res3 control")
	}

	// fourth query, ask for the last 2 CardInfo in realm r0
	expect4 := []credentials.CardInfo{infos[16], infos[24]}
	qry4 := credentials.CardQuery{RealmId: r0, Limit: 255, MinId: (infos[8].ID + 1)}
	res4, err := store.ListInfo(qry4)
	if nil != err {
		t.Fatalf("failed ListInfo(%v), got error %v", qry4, err)
	}
	if !reflect.DeepEqual(res4, expect4) {
		t.Error("failed res4 control")
	}
}

func initCard(card *credentials.Card) error {
	realmId := make([]byte, 32)
	rand.Read(realmId)
	card.RealmId = realmId

	cardId := make([]byte, 32)
	rand.Read(cardId)
	card.IdToken = cardId

	keypair, err := ecdh.X25519().GenerateKey(rand.Reader)
	if nil != err {
		return err
	}
	card.Kh = credentials.PrivateKeyHandle{PrivateKey: keypair}

	psk := make([]byte, 32)
	rand.Read(psk)
	card.Psk = psk

	card.AppName = "Test App"

	return nil
}

func printDB(t *testing.T, dbpath string) error {
	db, err := bolt.Open(dbpath, 0600, nil)
	if nil != err {
		return wrapError(err, "failed bolt.Open")
	}
	return db.View(func(tx *bolt.Tx) error {

		var err error
		var bucket *bolt.Bucket
		for _, bucketname := range []string{"cardTbl", "realmIdx", "tokenIdx"} {
			bucket = tx.Bucket([]byte(bucketname))
			t.Logf("%s bucket:", bucketname)
			err = bucket.ForEach(func(k, v []byte) error {
				t.Logf("    %X: %d bytes", k, len(v))

				return nil
			})
			if nil != err {
				return wrapError(err, "failed %s.ForEach", bucketname)
			}
		}

		return err

	})
}
