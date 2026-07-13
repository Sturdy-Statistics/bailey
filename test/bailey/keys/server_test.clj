(ns bailey.keys.server-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [babashka.fs :as fs]
   [sturdy.fs :as sfs]
   [taoensso.tempel :as tempel]
   [bailey.core :as bailey]
   [bailey.keys.server :as server]
   [bailey.keys.longterm :as longterm]
   [bailey.test-support :as ts]
   [taoensso.truss :refer [throws?]])
  (:import
   (java.util Arrays)))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Test Helpers & Mocks

(def ^:dynamic *test-secrets-dir* nil)
(def ^:dynamic *test-resources-dir* nil)
(def ^:dynamic *test-keychain-path* nil)
(def ^:dynamic *mock-tpm-password* (.getBytes "mock-tpm-password" "US-ASCII"))

(defn mock-read-password []
  (Arrays/copyOf *mock-tpm-password* (alength *mock-tpm-password*)))

(defn with-test-env [f]
  ;; Create unique temp dirs for every test run
  (let [secrets   (fs/create-temp-dir {:prefix "test-secrets"})
        key-path  (fs/path secrets "keychain.encrypted")
        resources (fs/create-temp-dir {:prefix "test-resources"})]
    (binding [*test-secrets-dir* (str secrets)
              *test-resources-dir* (str resources)
              *test-keychain-path* (str key-path)]
      (try
        ;; 1. Run the "Offline Admin" setup to generate backup keys
        ;;    (We mock the password prompt by passing it directly)
        (ts/with-quiet-logging
          (longterm/generate-longterm!
           {:secrets-dir   (str secrets)
            :resources-dir (str resources)
            :password      "some-special-admin-backup-password"}))

        ;; 2. Mock the classpath loader.
        ;;    Since we can't write to the real classpath at runtime, we override
        ;;    the function to read from our temp folder instead.
        (with-redefs [server/load-backup-public-key
                      (fn []
                        (let [p (fs/path resources "tempel_server_keys" "backup_pub.key")]
                          (reset! @#'server/backup-public-key* (tempel/keychain-thaw-public (sfs/slurp-bytes p)))))]

          (f))

        (finally
          (fs/delete-tree secrets)
          (fs/delete-tree resources))))))

(use-fixtures :each with-test-env)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest test-happy-path
  (testing "Server initializes and performs basic encryption"
    ;; Init
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [secret   (.getBytes "my-secret-data")
          enc      (bailey/encrypt secret)
          dec      (bailey/decrypt enc)]

      (is (not (tempel/ba= secret enc)) "Ciphertext should differ from plaintext")
      (is (tempel/ba= secret dec) "Decryption should restore original data"))))

(deftest test-key-rotation
  (testing "Key rotation preserves access to old data while securing new data"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [data-v1      (.getBytes "data-written-before-rotation")
          enc-v1       (bailey/encrypt data-v1)
          old-kc       @@#'server/server-keychain!!*]

      ;; PERFORM ROTATION
      (server/rotate-server-keys! mock-read-password)

      (let [data-v2      (.getBytes "data-written-after-rotation")
            enc-v2       (bailey/encrypt data-v2)
            new-kc       @@#'server/server-keychain!!*]

        (testing "Backward compatibility"
          (is (tempel/ba= data-v1 (bailey/decrypt enc-v1))
              "Should still be able to decrypt OLD data"))

        (testing "Forward operation"
          (is (tempel/ba= data-v2 (bailey/decrypt enc-v2))
              "Should be able to decrypt NEW data"))

        (testing "Old cannot decrypt new"
          (is (throws? :any
                       (tempel/decrypt-with-symmetric-key
                        enc-v2
                        old-kc))))

        (testing "New can decrypt old"
          (is (tempel/ba=
               data-v1
               (tempel/decrypt-with-symmetric-key
                enc-v1
                new-kc))))))))

(deftest test-key-rotation-rejects-wrong-password
  (testing "Key rotation rejects a password that cannot unlock the on-disk keychain"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [secret            (.getBytes "data-written-before-rejected-rotation")
          encrypted         (bailey/encrypt secret)
          keychain-before   @@#'server/server-keychain!!*
          file-before       (sfs/slurp-bytes *test-keychain-path*)
          rejected-password (.getBytes "wrong-tpm-password" "US-ASCII")]

      (is (throws? :any
                   (server/rotate-server-keys!
                    (constantly rejected-password)))
          "Rotation should fail when the supplied password cannot decrypt the current file")

      (is (Arrays/equals file-before (sfs/slurp-bytes *test-keychain-path*))
          "Rejected rotation must not modify the keychain file")
      (is (identical? keychain-before @@#'server/server-keychain!!*)
          "Rejected rotation must not replace the in-memory keychain")
      (is (tempel/ba= secret (bailey/decrypt encrypted))
          "The existing in-memory keychain should remain usable")
      (is (every? zero? rejected-password)
          "The rejected password byte array should be zeroed")

      ;; Simulate a process restart and prove the original password still unlocks the file.
      (reset! @#'server/server-keychain!!* nil)
      (bailey/init! {:keychain-path *test-keychain-path*
                     :read-server-password!! mock-read-password})
      (is (tempel/ba= secret (bailey/decrypt encrypted))
          "The original password should still work after a rejected rotation"))))

(deftest test-disaster-recovery-file-level
  (testing "If TPM password is lost, we can recover the keychain file using offline admin keys"

    ;; 1. Setup normal server
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [secret (.getBytes "critical-business-data")
          enc    (bailey/encrypt secret)]

      ;; 2. DISASTER: "Forget" the server memory
      (reset! @#'server/server-keychain!!* nil)

      ;; 3. RECOVERY: Simulate Admin using the "Safe" key
      (let [path-to-encrypted-kc *test-keychain-path*
            path-to-offline-kc   (fs/path *test-secrets-dir* "OFFLINE_backup_keychain.enc")
            recovered-server-kc
            (server/recover-keychain-file
             path-to-encrypted-kc
             path-to-offline-kc
             "some-special-admin-backup-password")]

        ;; 4. Verify we can now decrypt the data
        #_{:clj-kondo/ignore [:redundant-let]}
        (let [decrypted (tempel/decrypt-with-symmetric-key enc recovered-server-kc)]
          (is (tempel/ba= secret decrypted) "Recovered keychain should decrypt data"))))))

(deftest test-belt-and-suspenders
  (testing "Data encrypted with include-backup? can be recovered even if server keychain is DELETED"

    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [secret (.getBytes "nuclear-launch-codes")
          ;; Encrypt using the redundant method
          enc    (bailey/encrypt-critical secret)]

      ;; DISASTER: Delete the server keychain file entirely!
      (fs/delete *test-keychain-path*)
      (reset! @#'server/server-keychain!!* nil)

      ;; RECOVERY: We don't need the server keychain. We use the offline key directly.
      (let [path-to-offline-kc (fs/path *test-secrets-dir* "OFFLINE_backup_keychain.enc")

            offline-kc (tempel/keychain-decrypt
                        (sfs/slurp-bytes path-to-offline-kc)
                        {:password "some-special-admin-backup-password"})

            ;; Decrypt data directly with backup key
            decrypted (server/decrypt-backup {:encrypted-bytes enc
                                              :backup-full-keychain offline-kc})]

        (is (tempel/ba= secret decrypted))))))

(deftest test-string-wrappers
  (testing "String convenience wrappers handle UTF-8 correctly"

    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    ;; We use emojis to prove UTF-8 encoding is working
    (let [original "my-secret-data-🐶"
          enc      (bailey/encrypt-string original)
          dec      (bailey/decrypt-string enc)]

      ;; 1. Check data integrity
      (is (= original dec)
          "Decrypted string should match original exactly")

      ;; 2. Check encryption actually happened
      ;; (Compare bytes because 'enc' is byte[] and 'original' is string)
      (is (not (java.util.Arrays/equals (.getBytes original "UTF-8") enc))
          "Ciphertext bytes should differ from plaintext bytes"))))

(deftest test-inter-server-communication
  (testing "Servers can export public keys and use them for asymmetric encryption"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [server-a-pub (bailey/export-public-key)
          secret-msg   (.getBytes "top-secret-inter-server-payload" "UTF-8")

          ;; Simulate Server B encrypting a message FOR Server A
          ;; Server B uses Server A's thawed public key
          enc-for-a    (bailey/encrypt-for-recipient secret-msg server-a-pub)

          ;; Server A decrypts the message using its own keychain
          decrypted    (bailey/decrypt-asymmetric enc-for-a)]

      (is (not (tempel/ba= secret-msg enc-for-a)) "Ciphertext should differ from plaintext")
      (is (tempel/ba= secret-msg decrypted) "Server A should recover the exact payload"))))

(deftest test-ciphertext-tampering
  (testing "Modified ciphertext is rejected, preventing tampering attacks"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [secret   (.getBytes "sensitive-financial-data")
          enc      (bailey/encrypt secret)
          tampered (byte-array (alength ^bytes enc))]

      ;; Copy the ciphertext and flip one byte at the end
      (System/arraycopy enc 0 tampered 0 (alength ^bytes enc))
      (aset-byte tampered
                 (dec (alength ^bytes tampered))
                 (byte (inc (aget ^bytes tampered (dec (alength ^bytes tampered))))))

      (is (throws? :any (bailey/decrypt tampered))
          "Decryption must throw an exception if the ciphertext is altered"))))

(deftest test-unauthorized-asymmetric-recipient
  (testing "A third party cannot decrypt payloads intended for this server"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (let [server-a-pub (bailey/export-public-key)
          secret-msg   (.getBytes "for-your-eyes-only")
          enc-for-a    (bailey/encrypt-for-recipient secret-msg server-a-pub)

          ;; "Eve" creates her own valid keychain
          eve-kc       (tempel/keychain {})]

      (is (throws? :any
                   (tempel/decrypt-with-1-keypair enc-for-a eve-kc))
          "Decryption must fail if attempted by a keypair other than the intended recipient"))))

(deftest test-operational-edge-cases
  (testing "System halts on incorrect server passwords"
    ;; 1. Initialize the system properly to create the file
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    ;; 2. Simulate a restart by wiping the atom
    (reset! @#'server/server-keychain!!* nil)

    ;; 3. Attempt to initialize with a bad TPM secret
    (let [bad-tpm-fn (fn [] (.getBytes "wrong-tpm-password" "US-ASCII"))]
      (is (throws? :any
                   (bailey/init! {:keychain-path *test-keychain-path*
                                  :read-server-password!! bad-tpm-fn}))
          "Init should throw if the existing keychain cannot be unlocked")))

  (testing "Truss boundaries catch nil inputs immediately"
    (bailey/init! {:keychain-path *test-keychain-path*
                   :read-server-password!! mock-read-password})

    (is (throws? :any (bailey/encrypt nil)))
    (is (throws? :any (bailey/decrypt nil)))))
