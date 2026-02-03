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

            ;; Admin unlocks the offline keychain
            offline-kc (tempel/keychain-decrypt
                         (sfs/slurp-bytes path-to-offline-kc)
                         {:password "some-special-admin-backup-password"})

            ;; Admin unlocks the server keychain file using the offline keychain
            recovered-server-kc
            (tempel/keychain-decrypt
              (sfs/slurp-bytes path-to-encrypted-kc)
              {:backup-key offline-kc})]

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
