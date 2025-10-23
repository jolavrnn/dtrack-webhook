package cache

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type CacheItem struct {
	Data      []byte
	Timestamp time.Time
}

type CacheManager struct {
	cache      map[string]CacheItem
	mutex      sync.Mutex
	ttlSeconds int
	log        *logrus.Logger
}

func NewCacheManager(ttlSeconds int) *CacheManager {
	return &CacheManager{
		cache:      make(map[string]CacheItem),
		ttlSeconds: ttlSeconds,
		log:        logrus.New(),
	}
}

func (cm *CacheManager) Set(key string, data []byte) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.cache[key] = CacheItem{
		Data:      data,
		Timestamp: time.Now(),
	}
}

func (cm *CacheManager) Get(key string) ([]byte, bool) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	item, exists := cm.cache[key]
	if !exists {
		return nil, false
	}
	return item.Data, true
}

func (cm *CacheManager) Delete(key string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.cache, key)
}

func (cm *CacheManager) Cleanup() {
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		cm.mutex.Lock()
		for k, v := range cm.cache {
			if now.Sub(v.Timestamp).Seconds() > float64(cm.ttlSeconds) {
				delete(cm.cache, k)
				cm.log.WithField("key", k).Debug("Cache expired and removed")
			}
		}
		cm.mutex.Unlock()
	}
}

func (cm *CacheManager) Size() int {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	return len(cm.cache)
}
