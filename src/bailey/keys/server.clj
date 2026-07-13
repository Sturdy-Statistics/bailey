(ns bailey.keys.server
  (:require
   [babashka.fs :as fs]
   [sturdy.fs :as sfs]
   [clojure.java.io :as io]

   [bailey.util :as u]

   [taoensso.tempel :as tempel]
   [taoensso.truss :refer [have]]
   [taoensso.telemere :as t])
  (:import
   (java.io InputStream ByteArrayOutputStream)))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; state

(def ^:private backup-public-key* (atom nil))
(def ^:private server-keychain!!* (atom nil))
(def ^:private keychain-path* (atom nil))
(def ^:private initialized?* (atom false))

(defn- set-keychain-path [path]
  (reset! keychain-path* path))

(defn- require-keychain-path []
  (or @keychain-path*
      (throw (ex-info "Server key path not set. HINT: Did you run `init!`?" {}))))

(defn- require-server-key!! []
  (or @server-keychain!!*
      (throw (ex-info "Server key not loaded. HINT: Did you run `init!`?" {}))))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; backup key: Sturdy Stats; longterm

(defn- slurp-bytes
  "Read all bytes from an InputStream and return a byte[]."
  ^bytes [^InputStream is]
  (let [buf (byte-array 8192)
        baos (ByteArrayOutputStream.)]
    (loop []
      (let [n (.read is buf)]
        (when (pos? n)
          (.write baos buf 0 n)
          (recur))))
    (.toByteArray baos)))

(defn load-backup-public-key
  "Loads the baked-in public key from the Uberjar classpath."
  []
  (if-let [res (io/resource "tempel_server_keys/backup_pub.key")]
    (with-open [is (io/input-stream res)]
      (let [k (tempel/keychain-thaw-public (slurp-bytes is))]
        (reset! backup-public-key* k)
        k))
    (throw (ex-info "FATAL: Backup public key not found in resources."
                    {:hint "Did you run the generation script before building?"}))))

(defn- require-backup-key []
  (or @backup-public-key* (load-backup-public-key)))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; server key: specific to this server

(defn- ensure-tempel-keychain!
  [password!!]
  (let [p (require-keychain-path)]
    (when-not (fs/exists? p)
      (let [backup-key (require-backup-key)

            kc!!  (tempel/keychain {})
            kc-e  (tempel/keychain-encrypt kc!! {:pbkdf-nwf  :ref-1000-msecs
                                                 :password   (have bytes? password!!)
                                                 :backup-key backup-key})]
        (sfs/spit-bytes! p kc-e {:atomic? true
                                 :perms   "rw-------"})

        (t/log! {:level :info
                 :id ::create-server-keychain
                 :msg "saved server keychain"
                 :data {:full-keychain-path p}})))
    p))

(defn load-keychain!!
  [read-server-password!!]
  (let [pw!! (have bytes? (read-server-password!!))]

    (try
      (let [p     (ensure-tempel-keychain! pw!!)
            kc-e  (sfs/slurp-bytes p)
            kc!!  (or (tempel/keychain-decrypt kc-e {:password pw!!})
                      (throw (ex-info "FATAL: Failed to decrypt server keychain. Incorrect TPM password?"
                                      {:keychain-path p})))]
        (reset! server-keychain!!* kc!!)
        kc!!)
      (finally
        (u/zero-byte-array pw!!)))))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public API

(defn init!
  "Initialize server encryption keys exactly once during JVM startup.
   Treat any failure as fatal. Exactly one JVM process may own the keychain path."
  [{:keys [keychain-path read-server-password!!]}]
  (locking server-keychain!!*
    (when @initialized?*
      (throw (ex-info "Server encryption keys already initialized." {})))
    (set-keychain-path keychain-path)
    (load-backup-public-key)
    (let [kc!! (load-keychain!! read-server-password!!)]
      (reset! initialized?* true)
      kc!!)))

(defn encrypt
  "Encrypt data using the loaded server keychain.

  Note: This data is implicitly recoverable via the backup key
  because the keychain itself is recoverable.

  If `include-backup?` is truthy, also perform asymmetric encryption
  using the backup key.  This adds overhead, but guarantees the data
  can be decrypted even if BOTH the password AND the server keychain
  are lost."
  ^bytes [secret-data & {:keys [include-backup?]}]
  (let [kc!! (require-server-key!!)]
    (if-not include-backup?
      ;; simple encryption
      (tempel/encrypt-with-symmetric-key
       (have bytes? secret-data)
       kc!!)
      ;; encrypt with backup
      (let [backup-key (require-backup-key)]
        (tempel/encrypt-with-symmetric-key
         (have bytes? secret-data)
         kc!!
         {:backup-key backup-key})))))

(defn decrypt
  "Decrypt ciphertext made using `encrypt`."
  ^bytes [encrypted-bytes]
  (let [kc!! (require-server-key!!)]
    (tempel/decrypt-with-symmetric-key
     (have bytes? encrypted-bytes)
     kc!!)))

(defn- validate-tpm-password
  "validate that the TPM password can decrypt the keychain file"
  [pw!! kc-path]
  (let [old-kc-e (sfs/slurp-bytes kc-path)]
    (when-not (tempel/keychain-decrypt old-kc-e {:password pw!!})
      (throw (ex-info "FATAL: Failed to decrypt server keychain.  Incorrect TPM password?"
                      {:keychain-path kc-path})))))

(defn rotate-server-keys!
  "Generates a fresh symmetric key, promotes it to primary, and demotes existing keys.
   Updates the encrypted file on disk and the running in-memory atom.

   Requires the current TPM password to decrypt and re-encrypt the keychain file."
  [read-server-password!!]

  (let [p    (require-keychain-path)
        pw!! (have bytes? (read-server-password!!))]

    (try
      (locking server-keychain!!*
        (validate-tpm-password pw!! p)
        (let [old-kc!! (require-server-key!!)

              ;; add new key: (:random generates a fresh key, default priority is top/primary)
              rotated-kc!! (tempel/keychain-add-symmetric-key old-kc!! :random)

              ;; re-encrypt the updated keychain
              backup-key (require-backup-key)
              final-kc-e (tempel/keychain-encrypt
                          rotated-kc!!
                          {:pbkdf-nwf  :ref-1000-msecs
                           :password   pw!!
                           :backup-key backup-key})]

          ;; atomic write to disk
          (sfs/spit-bytes! p final-kc-e {:atomic? true
                                         :perms   "rw-------"})

          ;; update memory (hot swap)
          (reset! server-keychain!!* rotated-kc!!)

          (t/log! {:level :warn
                   :id    ::rotate-server-keys
                   :msg   "Server keys rotated successfully. Old keys retained for decryption."
                   :data  {:total-symmetric-keys (count (:symmetric-keys rotated-kc!!))}})))

      (finally
        (u/zero-byte-array pw!!)))))

(defn export-public-key
  "Freezes and returns this server's public key as a byte array."
  ^bytes []
  (let [kc!! (require-server-key!!)]
    (tempel/keychain-freeze-public kc!!)))

(defn encrypt-for-recipient
  "Encrypts secret-data so that it can only be decrypted by the owner of
   recipient-public-key-bytes."
  ^bytes [^bytes secret-data ^bytes recipient-public-key-bytes]
  (let [recipient-kc (tempel/keychain-thaw-public (have bytes? recipient-public-key-bytes))]
    (tempel/encrypt-with-1-keypair
     (have bytes? secret-data)
     recipient-kc)))

(defn decrypt-asymmetric
  "Decrypts data that was encrypted specifically for this server's public key."
  ^bytes [^bytes encrypted-bytes]
  (let [kc!! (require-server-key!!)]
    (tempel/decrypt-with-1-keypair
     (have bytes? encrypted-bytes)
     kc!!)))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; RECOVERY TOOL (For Admin use only, locally)

(defn recover-keychain-file
  "Decodes an encrypted keychain file using the OFFLINE full backup key.
   `backup-password` must be a String.
   Returns the usable server keychain."
  [path-to-encrypted-keychain path-to-offline-backup-keychain backup-password]
  (let [offline-kc (tempel/keychain-decrypt
                    (sfs/slurp-bytes path-to-offline-backup-keychain)
                    {:password (have string? backup-password)})

        server-kc-e (sfs/slurp-bytes path-to-encrypted-keychain)]

    ;; Use the Offline Keychain to unlock the Server Keychain
    (tempel/keychain-decrypt server-kc-e {:backup-key offline-kc})))

(defn decrypt-backup
  "Decodes an encrypted ciphertext using the OFFLINE full backup key."
  ^bytes [{:keys [encrypted-bytes backup-full-keychain]}]
  ;; There is intentionally no primary keychain: Tempel decrypts through the
  ;; offline keychain supplied as `:backup-key`.
  (tempel/decrypt-with-symmetric-key
   (have bytes? encrypted-bytes)
   nil
   {:backup-key backup-full-keychain}))
