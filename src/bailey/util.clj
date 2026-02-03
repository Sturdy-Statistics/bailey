(ns bailey.util)

(defn zero-byte-array [^bytes ba]
  (dotimes [i (alength ^bytes ba)]
    (aset-byte ^bytes ba (long i) 0x00))
  ba)
