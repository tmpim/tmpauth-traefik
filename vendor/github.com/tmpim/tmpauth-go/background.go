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

	debug  bool
	logger *log.Logger
}

func (w *BackgroundWorker) DebugLog(fmtString string, args ...interface{}) {
	if !w.debug {
		return
	}

	w.logger.Output(2, fmt.Sprintf(fmtString, args...))
}

func (w *BackgroundWorker) Start(logger *log.Logger, debug bool) {
	w.once.Do(func() {
		w.DebugLog("background worker started")
		w.debug = debug
		w.logger = logger
		go w.run()
	})
}

func (w *BackgroundWorker) MinValidationTime() time.Time {
	w.mutex.RLock()
	ret := w.minValidationTime
	w.mutex.RUnlock()
	return ret
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

	resp, err := http.Get("https://" + TmpAuthHost + "/tmpauth/cache")
	if err != nil {
		w.DebugLog("failed to get /tmpauth/cache: %v", err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.DebugLog("failed to get/tmpauth/cache: response not OK: %v", resp.Status)
		return
	}

	var response struct {
		CacheMinIat int64 `json:"cacheMinIat"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		w.DebugLog("failed to parse /tmpauth/cache response: %v", err)
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
		w.DebugLog("new minimum IAT (%v) before previous new minimum IAT (%v), ignoring update", newMinIat, prevMinIat)
	} else {
		w.DebugLog("minimum IAT successfully updated to %v (%v)", response.CacheMinIat, newMinIat)
	}
}
