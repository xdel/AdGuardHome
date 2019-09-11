package home

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuth(t *testing.T) {
	val := parseCookie("qwer=123456; session=asdfasdf")
	assert.True(t, val == "asdfasdf")

	os.Remove("./sessions.db")
	config.ourWorkingDir = "."
	a := InitSessions()

	assert.True(t, a.CheckSession("notfound") == -1)
	a.RemoveSession([]byte("notfound"))

	sess := getSession()
	sessStr := hex.EncodeToString(sess)

	// check expiration
	a.StoreSession(sess, uint32(time.Now().UTC().Unix()))
	assert.True(t, a.CheckSession(sessStr) == 1)

	// add session with TTL = 2 sec
	a.StoreSession(sess, uint32(time.Now().UTC().Unix()+2))
	assert.True(t, a.CheckSession(sessStr) == 0)

	a.Close()

	// load saved session
	a = InitSessions()

	// the session is still alive
	assert.True(t, a.CheckSession(sessStr) == 0)
	a.Close()

	time.Sleep(3 * time.Second)

	// load and remove expired sessions
	a = InitSessions()
	assert.True(t, a.CheckSession(sessStr) == -1)

	a.Close()
	os.Remove("./sessions.db")
}
