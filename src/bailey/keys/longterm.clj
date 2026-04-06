(ns bailey.keys.longterm
  (:require
   [babashka.fs :as fs]
   [sturdy.fs :as sfs]
   [taoensso.tempel :as tempel]
   [taoensso.truss :refer [have]]
   [taoensso.telemere :as t]))

(defn- read-password-securely []
  (if-let [env-pass (System/getenv "TEMPEL_ADMIN_PASSWORD")]
    env-pass
    (do
      (println "\n⚠️  Please enter the Admin Backup Password:")
      (let [c (or (System/console)
                  (throw (ex-info "No console available. Set TEMPEL_ADMIN_PASSWORD env var." {})))]
        (String. (.readPassword c))))))

(defn generate-longterm!
  [{:keys [secrets-dir password resources-dir force?]
    :or   {resources-dir "resources"}}]

  (let [pw        (or password (read-password-securely))
        _         (have string? pw)

        ;; files for offline storage: move to 1Password
        safe-dir  (fs/path secrets-dir)
        full-path (fs/path safe-dir "OFFLINE_backup_keychain.enc")

        ;; files for the uberjar
        res-path  (fs/path resources-dir "tempel_server_keys" "backup_pub.key")]

    (when (and (not force?) (fs/exists? full-path))
      (t/log! {:level :warn :msg "Backup keys already exist. Aborting to prevent overwrite."})
      (t/stop-handlers!)
      (System/exit 1))

    (let [kc!!  (tempel/keychain {})
          kc-e  (tempel/keychain-encrypt
                 kc!!
                 {:pbkdf-nwf :ref-5000-msecs
                  :password  pw})
          pub   (tempel/keychain-freeze-public kc!!)]

      ;; write the full key
      (-> full-path
          (sfs/spit-bytes! kc-e {:atomic? true})
          sfs/chmod-400!)

      ;; write "resource" file (public only)
      (-> res-path
          (sfs/spit-bytes! pub {:atomic? true})
          ;; public keys generally usually stay 644
          (fs/set-posix-file-permissions "rw-r--r--"))

      (t/log! {:level :info
               :id    ::create-longterm-backup-keychain
               :msg   "Backup keychain generated successfully"
               :data  {:offline-storage (str full-path)
                       :runtime-resource (str res-path)}}))))
