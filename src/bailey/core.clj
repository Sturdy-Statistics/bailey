(ns bailey.core
  "Bailey: Hardware-bound security for Clojure applications.

   This namespace provides the public API for initializing the secure
   environment, encrypting/decrypting data, and managing key rotation."
  (:require
   [bailey.keys.server :as server]
   [bailey.keys.longterm :as admin]))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 1. Build-Time / Admin Tools
;;;    Run these from your laptop or CI environment.

(defn generate-backup-keys!
  "Generates the offline 'Break Glass' identity.

   - Writes the FULL keychain (Private + Public) to `secrets-dir` (Keep this safe/offline!).
   - Writes the PUBLIC key to `resources-dir` (Commit this to Git).

   This must be run *before* building your Uberjar."
  [opts]
  (admin/generate-longterm! opts))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 2. Runtime / Server Lifecycle
;;;    Run these inside your application.

(defn init!
  "Initializes the security subsystem.

   - Loads the embedded backup public key from the classpath.
   - Loads (or creates) the server keychain from `keychain-path`.
   - Unlocks the keychain using the TPM-sealed password.

   Arguments:
     keychain-path          - path to save server keys
     read-server-password!! - (fn []) returning byte[] of the TPM password."
  [opts]
  (server/init! opts))

(defn rotate-keys!
  "Generates a fresh symmetric key and promotes it to primary.
   Existing keys are retained so old data remains readable.

   Use this for routine security maintenance."
  [read-server-password!!]
  (server/rotate-server-keys! read-server-password!!))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 3. Data Protection
;;;    The primary API for your application logic.

(defn encrypt
  "Encrypts `data` (byte[]) using the server's current primary key.
   Returns encrypted bytes."
  [data]
  (server/encrypt data))

(defn decrypt
  "Decrypts `ciphertext` (byte[]).
   Automatically selects the correct key from the server keychain."
  [ciphertext]
  (server/decrypt ciphertext))

(defn encrypt-string
  "Like `encrypt` but accepts a string as an argument.
   Encodes the string to UTF-8 before encrypting.

   NOTE: Strings are immutable and cannot be zero'd. If possible,
   alter your workflow to use byte[] instead.

   Returns encrypted bytes."
  [s]
  (when s
    (server/encrypt (.getBytes s "UTF-8"))))

(defn decrypt-string
  "Like `decrypt` but returns a string.
   Assumes the decrypted bytes are UTF-8 text.

   NOTE: Strings are immutable and cannot be zero'd. If possible,
   alter your workflow to use byte[] instead.

   Returns decrypted string."
  [ciphertext]
  (when ciphertext
    (String. (server/decrypt ciphertext) "UTF-8")))

(defn encrypt-critical
  "Encrypts data with 'Belt and Suspenders' protection.

   Use this for data that MUST be recoverable even if the server keychain
   file is corrupted or deleted (e.g., highly critical configs).

   WARNING: Adds significant size overhead (~500 bytes)."
  [data]
  (server/encrypt data {:include-backup? true}))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 4. Inter-Server Communication
;;;    Tools for securing payloads between distinct servers.

(defn export-public-key
  "Returns this server's public key as a byte array.
   Share this with other servers to allow them to encrypt payloads intended
   specifically for this server."
  ^bytes []
  (server/export-public-key))

(defn encrypt-for-recipient
  "Encrypts `data` (byte[]) for another server using its public key.
   Returns encrypted bytes."
  ^bytes [^bytes data ^bytes recipient-public-key-bytes]
  (server/encrypt-for-recipient data recipient-public-key-bytes))

(defn decrypt-asymmetric
  "Decrypts `ciphertext` (byte[]) that was encrypted for this server's
   public key."
  ^bytes [^bytes ciphertext]
  (server/decrypt-asymmetric ciphertext))
