package pmt

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type GPayKeysDownloader struct {
	url                     string
	stateLock               sync.Mutex
	fetchDataLock           sync.Mutex
	cachedData              string
	cachedTime              time.Time
	cacheExpirationDuration time.Duration
}

func NewGPayKeysDownloader(opts ...KeysDownloaderOption) (*GPayKeysDownloader, error) {
	d := &GPayKeysDownloader{}
	for _, opt := range opts {
		opt(d)
	}

	err := d.validate()
	if err != nil {
		return nil, err
	}

	return d, nil
}

func (d *GPayKeysDownloader) Download() (string, error) {
	data := d.getCachedData()
	if len(data) > 0 {
		return data, nil
	}

	d.fetchDataLock.Lock()
	defer d.fetchDataLock.Unlock()

	return d.fetchAndCacheData()
}

func (d *GPayKeysDownloader) fetchAndCacheData() (string, error) {
	resp, err := http.DefaultClient.Get(d.url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	d.stateLock.Lock()
	defer d.stateLock.Unlock()

	d.cachedTime = time.Now()
	d.cachedData = string(data)
	d.cacheExpirationDuration = getExpirationDuration(resp.Header)
	return d.cachedData, nil
}

func (d GPayKeysDownloader) hasNonExpiredCachedData() bool {
	return !time.Now().After(d.cachedTime.Add(d.cacheExpirationDuration))
}

func (d GPayKeysDownloader) shouldRefreshCachedData() bool {
	return !time.Now().After(d.cachedTime.Add(d.cacheExpirationDuration / 2))
}

func (d GPayKeysDownloader) getCachedData() string {
	d.stateLock.Lock()
	defer d.stateLock.Unlock()

	if d.hasNonExpiredCachedData() {
		if d.shouldRefreshCachedData() {
			go func() {
				d.fetchDataLock.Lock()
				defer d.fetchDataLock.Unlock()

				d.fetchAndCacheData()
			}()
		}

		return d.cachedData
	}

	return ""
}

func (d GPayKeysDownloader) validate() error {
	u, err := url.Parse(d.url)
	if err != nil {
		return err
	}

	if u.Scheme != "https" {
		return errors.New("url must point to a HTTPs server")
	}

	return nil
}

var maxAgePattern = regexp.MustCompile(`\s*max-age\s*=\s*(\d+)\s*`)

func getExpirationDuration(h http.Header) time.Duration {
	c := h.Get("Cache-Control")
	if len(c) != 0 {
		for _, arg := range strings.Split(c, ",") {
			res := maxAgePattern.FindAllStringSubmatch(arg, -1)
			if len(res) > 0 && len(res[0]) > 1 {
				durInSeconds, err := strconv.Atoi(res[0][1])
				if err != nil || durInSeconds < 0 {
					return 0
				}

				return time.Duration(durInSeconds) * time.Second
			}
		}
	}

	return 0
}
