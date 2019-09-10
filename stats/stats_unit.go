package stats

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	bolt "github.com/etcd-io/bbolt"
)

const (
	maxDomains = 100 // max number of top domains to store in file or return via Get()
	maxClients = 100 // max number of top clients to store in file or return via Get()
)

// statsCtx - global context
type statsCtx struct {
	limit    int            // maximum time we need to keep data for (in hours)
	filename string         // database file name
	unitID   unitIDCallback // user function which returns the current unit ID
	db       *bolt.DB

	unit     *unit      // the current unit
	unitLock sync.Mutex // protect 'unit'
}

// data for 1 time unit
type unit struct {
	id int // unit ID.  Default: absolute hour since Jan 1, 1970

	nTotal  int   // total requests
	nResult []int // number of requests per one result
	timeSum int   // sum of processing time of all requests (usec)

	// top:
	domains        map[string]int // number of requests per domain
	blockedDomains map[string]int // number of blocked requests per domain
	clients        map[string]int // number of requests per client
}

// name-count pair
type countPair struct {
	Name  string
	Count uint
}

// structure for storing data in file
type unitDB struct {
	NTotal  uint
	NResult []uint

	Domains        []countPair
	BlockedDomains []countPair
	Clients        []countPair

	TimeAvg uint // usec
}

func createObject(filename string, limitDays int, unitID unitIDCallback) (*statsCtx, error) {
	s := statsCtx{}
	s.limit = limitDays * 24
	s.filename = filename
	s.unitID = newUnitID
	if unitID != nil {
		s.unitID = unitID
	}

	if !s.dbOpen() {
		return nil, fmt.Errorf("open database")
	}

	id := s.unitID()
	tx := s.beginTxn(true)
	var udb *unitDB
	if tx != nil {
		log.Tracef("Deleting old units...")
		firstID := id - s.limit - 1
		unitDel := 0
		forEachBkt := func(name []byte, b *bolt.Bucket) error {
			id := btoi(name)
			if id < firstID {
				err := tx.DeleteBucket(name)
				if err != nil {
					log.Debug("tx.DeleteBucket: %s", err)
				}
				log.Debug("Stats: deleted unit %d", id)
				unitDel++
				return nil
			}
			return fmt.Errorf("")
		}
		_ = tx.ForEach(forEachBkt)

		udb = s.loadUnitFromDB(tx, id)

		if unitDel != 0 {
			s.commitTxn(tx)
		} else {
			_ = tx.Rollback()
		}
	}

	u := unit{}
	s.initUnit(&u, id)
	if udb != nil {
		deserialize(&u, udb)
	}
	s.unit = &u

	go s.periodicFlush()

	log.Debug("Stats: initialized")
	return &s, nil
}

func (s *statsCtx) dbOpen() bool {
	var err error
	log.Tracef("db.Open...")
	s.db, err = bolt.Open(s.filename, 0644, nil)
	if err != nil {
		log.Error("Stats: open DB: %s: %s", s.filename, err)
		return false
	}
	log.Tracef("db.Open")
	return true
}

// Atomically swap the currently active unit with a new value
// Return old value
func (s *statsCtx) swapUnit(new *unit) *unit {
	s.unitLock.Lock()
	u := s.unit
	s.unit = new
	s.unitLock.Unlock()
	return u
}

// Get unit ID for the current hour
func newUnitID() int {
	return int(time.Now().Unix() / (60 * 60))
}

// Initialize a unit
func (s *statsCtx) initUnit(u *unit, id int) {
	u.id = id
	u.nResult = make([]int, rLast)
	u.domains = make(map[string]int)
	u.blockedDomains = make(map[string]int)
	u.clients = make(map[string]int)
}

// Open a DB transaction
func (s *statsCtx) beginTxn(wr bool) *bolt.Tx {
	db := s.db
	if db == nil {
		return nil
	}

	log.Tracef("db.Begin...")
	tx, err := db.Begin(wr)
	if err != nil {
		log.Error("db.Begin: %s", err)
		return nil
	}
	log.Tracef("db.Begin")
	return tx
}

func (s *statsCtx) commitTxn(tx *bolt.Tx) {
	err := tx.Commit()
	if err != nil {
		log.Debug("tx.Commit: %s", err)
		return
	}
	log.Tracef("tx.Commit")
}

// Get unit name
func unitName(id int) []byte {
	return itob(id)
}

// Convert integer to 8-byte array (big endian)
func itob(v int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// Convert 8-byte array (big endian) to integer
func btoi(b []byte) int {
	return int(binary.BigEndian.Uint64(b))
}

// Flush the current unit to DB and delete an old unit when a new hour is started
func (s *statsCtx) periodicFlush() {
	for {
		s.unitLock.Lock()
		ptr := s.unit
		s.unitLock.Unlock()
		if ptr == nil {
			break
		}

		id := s.unitID()
		if ptr.id == id {
			time.Sleep(time.Second)
			continue
		}

		nu := unit{}
		s.initUnit(&nu, id)
		u := s.swapUnit(&nu)
		udb := serialize(u)

		tx := s.beginTxn(true)
		if tx == nil {
			continue
		}
		ok1 := s.flushUnitToDB(tx, u.id, udb)
		ok2 := s.deleteUnit(tx, id-s.limit)
		if ok1 || ok2 {
			s.commitTxn(tx)
		} else {
			_ = tx.Rollback()
		}
	}
	log.Tracef("periodicFlush() exited")
}

// Delete unit's data from file
func (s *statsCtx) deleteUnit(tx *bolt.Tx, id int) bool {
	err := tx.DeleteBucket(unitName(id))
	if err != nil {
		log.Tracef("bolt DeleteBucket: %s", err)
		return false
	}
	log.Debug("Stats: deleted unit %d", id)
	return true
}

func convertMapToArray(m map[string]int, max int) []countPair {
	a := []countPair{}
	for k, v := range m {
		pair := countPair{}
		pair.Name = k
		pair.Count = uint(v)
		a = append(a, pair)
	}
	less := func(i, j int) bool {
		if a[i].Count >= a[j].Count {
			return true
		}
		return false
	}
	sort.Slice(a, less)
	if max > len(a) {
		max = len(a)
	}
	return a[:max]
}

func convertArrayToMap(a []countPair) map[string]int {
	m := map[string]int{}
	for _, it := range a {
		m[it.Name] = int(it.Count)
	}
	return m
}

func serialize(u *unit) *unitDB {
	udb := unitDB{}
	udb.NTotal = uint(u.nTotal)
	for _, it := range u.nResult {
		udb.NResult = append(udb.NResult, uint(it))
	}
	if u.nTotal != 0 {
		udb.TimeAvg = uint(u.timeSum / u.nTotal)
	}
	udb.Domains = convertMapToArray(u.domains, maxDomains)
	udb.BlockedDomains = convertMapToArray(u.blockedDomains, maxDomains)
	udb.Clients = convertMapToArray(u.clients, maxClients)
	return &udb
}

func deserialize(u *unit, udb *unitDB) {
	u.nTotal = int(udb.NTotal)
	for _, it := range udb.NResult {
		u.nResult = append(u.nResult, int(it))
	}
	u.domains = convertArrayToMap(udb.Domains)
	u.blockedDomains = convertArrayToMap(udb.BlockedDomains)
	u.clients = convertArrayToMap(udb.Clients)
	u.timeSum = int(udb.TimeAvg) * u.nTotal
}

func (s *statsCtx) flushUnitToDB(tx *bolt.Tx, id int, udb *unitDB) bool {
	log.Tracef("Flushing unit %d", id)

	bkt, err := tx.CreateBucketIfNotExists(unitName(id))
	if err != nil {
		log.Error("tx.CreateBucketIfNotExists: %s", err)
		return false
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(udb)
	if err != nil {
		log.Error("gob.Encode: %s", err)
		return false
	}

	err = bkt.Put([]byte{0}, buf.Bytes())
	if err != nil {
		log.Error("bkt.Put: %s", err)
		return false
	}

	return true
}

func (s *statsCtx) loadUnitFromDB(tx *bolt.Tx, id int) *unitDB {
	bkt := tx.Bucket(unitName(id))
	if bkt == nil {
		return nil
	}

	log.Tracef("Loading unit %d", id)

	var buf bytes.Buffer
	buf.Write(bkt.Get([]byte{0}))
	dec := gob.NewDecoder(&buf)
	udb := unitDB{}
	err := dec.Decode(&udb)
	if err != nil {
		log.Error("gob Decode: %s", err)
		return nil
	}

	return &udb
}

func convertTopArray(a []countPair) []map[string]uint {
	m := []map[string]uint{}
	for _, it := range a {
		ent := map[string]uint{}
		ent[it.Name] = it.Count
		m = append(m, ent)
	}
	return m
}

func (s *statsCtx) Configure(limit int) {
	if limit < 0 {
		return
	}
	s.limit = limit * 24
	log.Debug("Stats: set limit: %d", limit)
}

func (s *statsCtx) Close() {
	u := s.swapUnit(nil)
	udb := serialize(u)
	tx := s.beginTxn(true)
	if tx != nil {
		if s.flushUnitToDB(tx, u.id, udb) {
			s.commitTxn(tx)
		} else {
			_ = tx.Rollback()
		}
	}

	if s.db != nil {
		log.Tracef("db.Close...")
		_ = s.db.Close()
		log.Tracef("db.Close")
	}

	log.Debug("Stats: closed")
}

func (s *statsCtx) Clear() {
	tx := s.beginTxn(true)
	if tx != nil {
		db := s.db
		s.db = nil
		_ = tx.Rollback()
		// the active transactions can continue using database,
		//  but no new transactions will be opened
		_ = db.Close()
		log.Tracef("db.Close")
		// all active transactions are now closed
	}

	u := unit{}
	s.initUnit(&u, s.unitID())
	_ = s.swapUnit(&u)

	err := os.Remove(s.filename)
	if err != nil {
		log.Error("os.Remove: %s", err)
	}

	_ = s.dbOpen()

	log.Debug("Stats: cleared")
}

func (s *statsCtx) Update(e Entry) {
	if e.Result == 0 ||
		len(e.Domain) == 0 ||
		!(len(e.Client) == 4 || len(e.Client) == 16) {
		return
	}
	client := e.Client.String()

	s.unitLock.Lock()
	u := s.unit

	u.nResult[e.Result]++

	if e.Result == RNotFiltered {
		u.domains[e.Domain]++
	} else {
		u.blockedDomains[e.Domain]++
	}

	u.clients[client]++
	u.timeSum += int(e.Time)
	u.nTotal++
	s.unitLock.Unlock()
}

/* Algorithm:
. Prepare array of N units, where N is the value of "limit" configuration setting
 . Load data for the most recent units from file
   If a unit with required ID doesn't exist, just add an empty unit
 . Get data for the current unit
. Process data from the units and prepare an output map object:
 * per time unit counters:
  * DNS-queries/time-unit
  * blocked/time-unit
  * safebrowsing-blocked/time-unit
  * parental-blocked/time-unit
  If time-unit is an hour, just add values from each unit to an array.
  If time-unit is a day, aggregate per-hour data into days.
 * top counters:
  * queries/domain
  * queries/blocked-domain
  * queries/client
  To get these values we first sum up data for all units into a single map.
  Then we get the pairs with the highest numbers (the values are sorted in descending order)
 * total counters:
  * DNS-queries
  * blocked
  * safebrowsing-blocked
  * safesearch-blocked
  * parental-blocked
  These values are just the sum of data for all units.
*/
// nolint (gocyclo)
func (s *statsCtx) GetData(timeUnit TimeUnit) map[string]interface{} {
	d := map[string]interface{}{}

	tx := s.beginTxn(false)
	if tx == nil {
		return nil
	}

	units := []*unitDB{} //per-hour units
	lastID := s.unitID()
	firstID := lastID - s.limit + 1
	for i := firstID; i != lastID; i++ {
		u := s.loadUnitFromDB(tx, i)
		if u == nil {
			u = &unitDB{}
			u.NResult = make([]uint, rLast)
		}
		units = append(units, u)
	}

	_ = tx.Rollback()

	s.unitLock.Lock()
	cu := serialize(s.unit)
	cuID := s.unit.id
	s.unitLock.Unlock()
	if cuID != lastID {
		units = units[1:]
	}
	units = append(units, cu)

	if len(units) != s.limit {
		log.Fatalf("len(units) != s.limit: %d %d", len(units), s.limit)
	}

	// per time unit counters:

	// 720 hours may span 31 days, so we skip data for the first day in this case
	firstDayID := (firstID + 24 - 1) / 24 * 24 // align_ceil(24)

	a := []uint{}
	if timeUnit == Hours {
		for _, u := range units {
			a = append(a, u.NTotal)
		}
	} else {
		var sum uint
		id := firstDayID
		nextDayID := firstDayID + 24
		for i := firstDayID - firstID; i != len(units); i++ {
			sum += units[i].NTotal
			if id == nextDayID {
				a = append(a, sum)
				sum = 0
				nextDayID += 24
			}
			id++
		}
		if id < nextDayID {
			a = append(a, sum)
		}
		if len(a) != s.limit/24 {
			log.Fatalf("len(a) != s.limit: %d %d", len(a), s.limit)
		}
	}
	d["dns_queries"] = a

	a = []uint{}
	if timeUnit == Hours {
		for _, u := range units {
			a = append(a, u.NResult[RFiltered])
		}
	} else {
		var sum uint
		id := firstDayID
		nextDayID := firstDayID + 24
		for i := firstDayID - firstID; i != len(units); i++ {
			sum += units[i].NResult[RFiltered]
			if id == nextDayID {
				a = append(a, sum)
				sum = 0
				nextDayID += 24
			}
			id++
		}
		if id < nextDayID {
			a = append(a, sum)
		}
	}
	d["blocked_filtering"] = a

	a = []uint{}
	if timeUnit == Hours {
		for _, u := range units {
			a = append(a, u.NResult[RSafeBrowsing])
		}
	} else {
		var sum uint
		id := firstDayID
		nextDayID := firstDayID + 24
		for i := firstDayID - firstID; i != len(units); i++ {
			sum += units[i].NResult[RSafeBrowsing]
			if id == nextDayID {
				a = append(a, sum)
				sum = 0
				nextDayID += 24
			}
			id++
		}
		if id < nextDayID {
			a = append(a, sum)
		}
	}
	d["replaced_safebrowsing"] = a

	a = []uint{}
	if timeUnit == Hours {
		for _, u := range units {
			a = append(a, u.NResult[RParental])
		}
	} else {
		var sum uint
		id := firstDayID
		nextDayID := firstDayID + 24
		for i := firstDayID - firstID; i != len(units); i++ {
			sum += units[i].NResult[RParental]
			if id == nextDayID {
				a = append(a, sum)
				sum = 0
				nextDayID += 24
			}
			id++
		}
		if id < nextDayID {
			a = append(a, sum)
		}
	}
	d["replaced_parental"] = a

	// top counters:

	m := map[string]int{}
	for _, u := range units {
		for _, it := range u.Domains {
			m[it.Name] += int(it.Count)
		}
	}
	a2 := convertMapToArray(m, maxDomains)
	d["top_queried_domains"] = convertTopArray(a2)

	m = map[string]int{}
	for _, u := range units {
		for _, it := range u.BlockedDomains {
			m[it.Name] += int(it.Count)
		}
	}
	a2 = convertMapToArray(m, maxDomains)
	d["top_blocked_domains"] = convertTopArray(a2)

	m = map[string]int{}
	for _, u := range units {
		for _, it := range u.Clients {
			m[it.Name] += int(it.Count)
		}
	}
	a2 = convertMapToArray(m, maxClients)
	d["top_clients"] = convertTopArray(a2)

	// total counters:

	sum := unitDB{}
	timeN := 0
	sum.NResult = make([]uint, rLast)
	for _, u := range units {
		sum.NTotal += u.NTotal
		sum.TimeAvg += u.TimeAvg
		if u.TimeAvg != 0 {
			timeN++
		}
		sum.NResult[RFiltered] += u.NResult[RFiltered]
		sum.NResult[RSafeBrowsing] += u.NResult[RSafeBrowsing]
		sum.NResult[RSafeSearch] += u.NResult[RSafeSearch]
		sum.NResult[RParental] += u.NResult[RParental]
	}

	d["num_dns_queries"] = sum.NTotal
	d["num_blocked_filtering"] = sum.NResult[RFiltered]
	d["num_replaced_safebrowsing"] = sum.NResult[RSafeBrowsing]
	d["num_replaced_safesearch"] = sum.NResult[RSafeSearch]
	d["num_replaced_parental"] = sum.NResult[RParental]

	avgTime := float64(0)
	if timeN != 0 {
		avgTime = float64(sum.TimeAvg/uint(timeN)) / 1000000
	}
	d["avg_processing_time"] = avgTime

	d["time_units"] = "hours"
	if timeUnit == Days {
		d["time_units"] = "days"
	}

	return d
}
