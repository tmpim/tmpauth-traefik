package tmpauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

var backgroundWorker = &BackgroundWorker{
	once:              new(sync.Once),
	mutex:             new(sync.RWMutex),
	minValidationTime: time.Now(),

	debug:  false,
	logger: nil,
}

type BackgroundWorker struct {
	once              *sync.Once
	mutex             *sync.RWMutex
	minValidationTime time.Time

	debug          bool
	logger         *log.Logger
	validationHost string
}

func (w *BackgroundWorker) DebugLog(str string) {
	if !w.debug {
		return
	}

	w.logger.Output(2, str)
}

func (w *BackgroundWorker) Start(logger *log.Logger, debug bool, validationHost ...string) {
	w.once.Do(func() {
		w.DebugLog("background worker started")
		w.debug = debug
		w.logger = logger
		if len(validationHost) > 0 {
			w.validationHost = validationHost[0]
		}
		go w.run()
	})
}

func (w *BackgroundWorker) MinValidationTime() time.Time {
	w.mutex.RLock()
	ret := w.minValidationTime
	w.mutex.RUnlock()
	return ret
}

func MinValidationTime() time.Time {
	return backgroundWorker.MinValidationTime()
}

func (w *BackgroundWorker) run() {
	w.updateMinimumIat()

	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		w.updateMinimumIat()
	}
}

func (w *BackgroundWorker) updateMinimumIat() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "tmpauth panic: updateMinimumIat: %v\n%s",
				r, string(debug.Stack()))
		}
	}()
	w.DebugLog("updating minimum IAT")

	validationHost := w.validationHost
	if validationHost == "" {
		validationHost = "https://" + TmpAuthHost
	}

	resp, err := http.Get(validationHost + "/tmpauth/cache")
	if err != nil {
		w.DebugLog(fmt.Sprintf("failed to get /tmpauth/cache: %v", err))
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.DebugLog(fmt.Sprintf("failed to get/tmpauth/cache: response not OK: %v", resp.Status))
		return
	}

	var response struct {
		CacheMinIat int64 `json:"cacheMinIat"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		w.DebugLog(fmt.Sprintf("failed to parse /tmpauth/cache response: %v", err))
		return
	}

	newMinIat := time.Unix(0, response.CacheMinIat*int64(time.Millisecond/time.Nanosecond))

	var prevMinIat time.Time

	w.mutex.Lock()
	if newMinIat.After(w.minValidationTime) {
		w.minValidationTime = newMinIat
	} else {
		prevMinIat = w.minValidationTime
	}
	w.mutex.Unlock()

	if !prevMinIat.IsZero() {
		w.DebugLog(fmt.Sprintf("new minimum IAT (%v) before previous new minimum IAT (%v), ignoring update", newMinIat, prevMinIat))
	} else {
		w.DebugLog(fmt.Sprintf("minimum IAT successfully updated to %v (%v)", response.CacheMinIat, newMinIat))
	}
}
