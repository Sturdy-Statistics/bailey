(ns bailey.test-support
  (:require
   [taoensso.telemere :as t]))

(defn- remove-all-handlers! []
  (doseq [h (keys (t/get-handlers))]
    (t/remove-handler! h)))

(defn run-quietly! [thunk]
  ;; Save current handlers, silence logging, run, restore.
  (let [saved-handlers (t/get-handlers)]
    (remove-all-handlers!)
    (t/add-handler! :noop (fn [_] nil))
    (try
      (thunk)
      (finally
        (remove-all-handlers!)
        (doseq [[k v] saved-handlers]
          (t/add-handler! k v))))))

(defmacro with-quiet-logging
  "Execute BODY with Telemere logging suppressed (no console/file output)."
  [& body]
  `(run-quietly! (fn [] ~@body)))
