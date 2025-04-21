package noise

import (
	"reflect"
	"strings"
	"testing"
)

const (
	halfKey = "0123456789ABCDEF"
	testKey = halfKey + halfKey
	ad1     = "additional data 01"
)

func TestCipherFactoryRegister(t *testing.T) {
	// first registration shall succeed, as mychacha is not in the registry currently
	err := RegisterAEAD("mychacha", AEADFactoryFunc(newChachaPoly1305))
	if nil != err {
		t.Fatalf("Failed registering mychacha, got error %v", err)
	}

	// second registration shall fail
	err = RegisterAEAD("mychacha", AEADFactoryFunc(newChachaPoly1305))
	if nil == err {
		t.Errorf("Oops, it was possible to register mychacha a second time")
	}
}

func TestCipherUse(t *testing.T) {
	ciphernames := []string{CIPHER_AES256_GCM, CIPHER_CHACHA20_POLY1305}
	for _, ciphername := range ciphernames {
		t.Run(ciphername, func(t *testing.T) {
			cipherfactory, err := GetAEADFactory(ciphername)
			if nil != err {
				t.Fatalf("Failed loading AEAD factory %s, got error %v", ciphername, err)
			}

			cipher := CipherState{}
			err = cipher.Init(cipherfactory)
			if nil != err {
				t.Fatalf("Failed cipher.Init, got error %v", err)
			}
			if cipher.HasKey() {
				t.Fatalf("Oops, cipher.HasKey() is true")
			}

			// when cipher does not contain a key it applies no encryption
			var result []byte
			plaintext := []byte("a test payload...")
			result, err = cipher.EncryptWithAd(nil, plaintext)
			if nil != err {
				t.Fatal("Failed EncryptWithAd when cipher has no key")
			}
			if !reflect.DeepEqual(result, plaintext) {
				t.Fatal("Oops, EncryptWithAd applied encryption when cipher has no key")
			}
			ciphertext := plaintext
			result, err = cipher.DecryptWithAd(nil, ciphertext)
			if nil != err {
				t.Fatal("Failed DecryptWithAd when cipher has no key")
			}
			if !reflect.DeepEqual(result, ciphertext) {
				t.Fatal("Oops, EncryptWithAd applied encryption when cipher has no key")
			}

			err = cipher.InitializeKey([]byte(testKey))
			if nil != err {
				t.Fatalf("Failed InitializeKey, got error %v", err)
			}
			for pos, nonce := range []uint64{1, 256, 517} {
				cipher.SetNonce(nonce)

				ciphertext, err = cipher.EncryptWithAd([]byte(ad1), plaintext)
				if nil != err {
					t.Fatalf("#%d: Failed EncryptWithAd, got error %v", pos, err)
				}

				// first attend to decrypt, it shall fail as internal nonce state should have changed
				result, err = cipher.DecryptWithAd([]byte(ad1), ciphertext)
				if nil == err {
					t.Fatalf("#%d: Oops, DecryptWithAd success with wrong nonce", pos)
				}

				// second attend to decrypt, it shall succeed
				cipher.SetNonce(nonce)
				result, err = cipher.DecryptWithAd([]byte(ad1), ciphertext)
				if nil != err {
					t.Fatalf("#%d: Failed DecryptWithAd, got error %v", pos, err)
				}
				if !reflect.DeepEqual(result, plaintext) {
					t.Fatalf("#%d, Failed plaintext control \n%s\n!=\n%s", pos, string(result), string(plaintext))
				}

				// third attend to decrypt, it shall fail as we use a different ad
				cipher.SetNonce(nonce)
				result, err = cipher.DecryptWithAd(nil, ciphertext)
				if nil == err {
					t.Fatalf("#%d: Oops, DecryptWithAd success with wrong additional data", pos)
				}
			}

			// zero inner key
			err = cipher.InitializeKey(nil)
			if nil != err {
				t.Fatalf("Failed cipher.InitializeKey(nil), got error %v", err)
			}
			if cipher.HasKey() {
				t.Fatalf("Oops, cipher.HasKey() is true after zeroing the key")
			}

			// when cipher does not contain a key it applies no encryption
			result, err = cipher.EncryptWithAd([]byte(ad1), plaintext)
			if nil != err {
				t.Fatal("Failed EncryptWithAd after cipher key has been zeroed")
			}
			if !reflect.DeepEqual(result, plaintext) {
				t.Fatal("Oops, EncryptWithAd applied encryption after key has been zeroed")
			}
			ciphertext = plaintext
			result, err = cipher.DecryptWithAd([]byte(ad1), ciphertext)
			if nil != err {
				t.Fatal("Failed DecryptWithAd after key has been zeroed")
			}
			if !reflect.DeepEqual(result, ciphertext) {
				t.Fatal("Oops, DecryptWithAd modified ciphertext after key has been zeroed")
			}

		})
	}
}

func TestCipherSizeLimit(t *testing.T) {
	factory, err := GetAEADFactory(CIPHER_CHACHA20_POLY1305)
	if nil != err {
		t.Fatalf("Failed loading AEAD factory %s, got error %v", CIPHER_CHACHA20_POLY1305, err)
	}
	cipher := CipherState{factory: factory}
	err = cipher.InitializeKey([]byte(testKey))
	if nil != err {
		t.Fatalf("Failed InitializeKey, got error %v", err)
	}

	const maxPlainTxt = msgMaxSize - cipherTagSize + 1
	plaintxt := make([]byte, maxPlainTxt)
	cipher.SetNonce(1024)
	ciphertxt, err := cipher.EncryptWithAd(nil, plaintxt[0:maxPlainTxt-1])
	if nil != err {
		t.Fatalf("Failed EncryptWithAd, got error %v", err)
	}
	_, err = cipher.EncryptWithAd(nil, plaintxt)
	if nil == err {
		t.Fatal("Oops, EncryptWithAd did not error, when plaintxt too large")
	}

	cipher.SetNonce(1024)
	_, err = cipher.DecryptWithAd(nil, ciphertxt)
	if nil != err {
		t.Fatalf("Failed DecryptWithAd got error %v", err)
	}

	// we can not produce a valid ciphertxt which is oversized
	// below test is a bit shaky as DecryptWithAd should always fail with invalidtxt
	// we check the error to see if it corresponds to a size problem
	invalidtxt := append(ciphertxt, 255)
	cipher.SetNonce(1024)
	_, err = cipher.DecryptWithAd(nil, invalidtxt)
	if nil == err || !strings.Contains(err.Error(), "(noise protocol size limit)") {
		t.Fatalf("Failed, DecryptWithAd did not error on cipher text size, got error %v", err)
	}

}
