// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exgjson"
	flag "maunium.net/go/mauflag"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/id"
)

type CreatePDU struct {
	AuthEvents     []string        `json:"auth_events"`
	PrevEvents     []string        `json:"prev_events"`
	Depth          int             `json:"depth"`
	Hashes         *Hashes         `json:"hashes,omitempty"`
	OriginServerTS int64           `json:"origin_server_ts"`
	Sender         id.UserID       `json:"sender"`
	StateKey       string          `json:"state_key"`
	Type           string          `json:"type"`
	Content        json.RawMessage `json:"content"`
}

type Hashes struct {
	SHA256 string `json:"sha256"`
}

var timestamp = flag.MakeFull("t", "timestamp", "Timestamp of the create event (defaults to current time)", strconv.FormatInt(time.Now().UnixMilli(), 10)).Int64()
var creator = flag.MakeFull("u", "user_id", "User ID of the room creator", "").String()
var prefix = flag.MakeFull("p", "prefix", "Prefix for the room ID", "").String()
var createContent = flag.MakeFull("c", "content", "Create event content", `{"room_version":"12"}`).String()
var threadCount = flag.MakeFull("k", "threads", "Number of threads to use for bruteforcing", "1").Uint16()
var threadIndexStart = flag.MakeFull("i", "index-start", "Starting index for thread IDs (useful for running multiple instances)", "0").Uint16()
var logInterval = flag.MakeFull("l", "log-interval", "How many hashes to check before logging status?", "1000000").Uint32()
var maxSeconds = flag.MakeFull("m", "max-seconds", "Time limit for the bruteforce in seconds (-1 for unlimited)", "30").Int()
var wantHelp, _ = flag.MakeHelpFlag()

const placeholderRandomness = "PLCEHOLD"
const placeholderSHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

var base64SHA256Length = base64.RawURLEncoding.EncodedLen(sha256.Size)

const maxPrefixLength = 12 // arbitrarily picked number that is probably already impossible

func main() {
	flag.SetHelpTitles(
		"matrix-rig - Vanity Room ID generator for Matrix.",
		"matrix-rig [-h] [-t timestamp] [-u user_id] [-p prefix] [-c creation_content] [-k threads] [-l log_interval] [-m max_seconds]",
	)
	err := flag.Parse()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, err.Error())
		flag.PrintHelp()
		os.Exit(3)
	} else if *wantHelp {
		flag.PrintHelp()
		os.Exit(3)
	}
	creatorUserID := id.UserID(*creator)
	if _, _, err := creatorUserID.Parse(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid user ID: %s\n", *creator)
		os.Exit(4)
	} else if !json.Valid([]byte(*createContent)) {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid create event content\n")
		os.Exit(4)
	} else if len(*prefix) > maxPrefixLength {
		_, _ = fmt.Fprintf(os.Stderr, "Prefix too long, must be at most %d characters\n", maxPrefixLength)
		os.Exit(4)
	}
	createContentJSON := json.RawMessage(*createContent)
	createContentJSON = exerrors.Must(sjson.SetBytes(createContentJSON, exgjson.Path("fi.mau.randomness"), placeholderRandomness))
	createPDU := &CreatePDU{
		AuthEvents:     []string{},
		PrevEvents:     []string{},
		Depth:          1,
		Hashes:         nil,
		OriginServerTS: *timestamp,
		Sender:         creatorUserID,
		StateKey:       "",
		Type:           "m.room.create",
		Content:        createContentJSON,
	}
	pduJSON := exerrors.Must(json.Marshal(createPDU))
	pduJSON = canonicaljson.CanonicalJSONAssumeValid(pduJSON)
	createPDU.Hashes = &Hashes{SHA256: placeholderSHA256}
	pduJSONWithHashField := exerrors.Must(json.Marshal(createPDU))
	pduJSONWithHashField = canonicaljson.CanonicalJSONAssumeValid(pduJSONWithHashField)
	var wg sync.WaitGroup
	for {
		if int(*threadIndexStart)+int(*threadCount) > math.MaxUint16 {
			_, _ = fmt.Fprintf(os.Stderr, "Thread index %d + %d exceeds uint16 limit\n", *threadIndexStart, *threadCount)
			break
		}
		wg.Add(int(*threadCount))
		for i := uint16(0); i < *threadCount; i++ {
			go doBruteforce(*threadIndexStart+i, bytes.Clone(pduJSON), bytes.Clone(pduJSONWithHashField), []byte(*prefix), *logInterval, wg.Done)
			time.Sleep(time.Duration(500 / *threadCount) * time.Millisecond)
		}
		if *maxSeconds < 0 {
			wg.Wait()
			fmt.Println("No solutions found, incrementing thread index start")
			*threadIndexStart += *threadCount
		} else {
			timeLimit := time.Duration(*maxSeconds) * time.Second
			time.Sleep(timeLimit)
			fmt.Println("No solution found in", timeLimit)
			break
		}
	}
	os.Exit(1)
}

func doBruteforce(threadID uint16, pduJSON, pduJSONWithHashField, prefix []byte, chunkSize uint32, doneFunc func()) {
	defer doneFunc()
	pduRandomIndex := bytes.Index(pduJSON, []byte(placeholderRandomness))
	pduHashRandomIndex := bytes.Index(pduJSONWithHashField, []byte(placeholderRandomness))
	pduHashIndex := bytes.Index(pduJSONWithHashField, []byte(placeholderSHA256))

	var i, chunks uint32
	maxChunks := math.MaxUint32 / chunkSize
	// 2 byte thread ID + 4 byte counter
	randomness := make([]byte, 6)
	binary.BigEndian.PutUint16(randomness[0:2], threadID)
	unsafeRandomnessUint32 := (*uint32)(unsafe.Pointer(&randomness[2]))
	randomnessEncodedLength := base64.RawURLEncoding.EncodedLen(len(randomness))
	if len(placeholderRandomness) != randomnessEncodedLength {
		panic("Placeholder randomness length mismatch")
	}
	pduRandomSlot := pduJSON[pduRandomIndex : pduRandomIndex+randomnessEncodedLength]
	pduWithHashRandomSlot := pduJSONWithHashField[pduHashRandomIndex : pduHashRandomIndex+randomnessEncodedLength]
	pduHashSlot := pduJSONWithHashField[pduHashIndex : pduHashIndex+base64SHA256Length]

	hasher := sha256.New()
	hashContainer := make([]byte, sha256.Size)
	eventID := make([]byte, base64SHA256Length)

	start := time.Now()
	lastChunk := start
	for {
		i++
		base64.RawURLEncoding.Encode(pduRandomSlot, randomness)
		copy(pduWithHashRandomSlot, pduRandomSlot)
		hasher.Reset()
		hasher.Write(pduJSON)
		hasher.Sum(hashContainer[:0])
		base64.RawStdEncoding.Encode(pduHashSlot, hashContainer)
		hasher.Reset()
		hasher.Write(pduJSONWithHashField)
		hasher.Sum(hashContainer[:0])
		base64.RawURLEncoding.Encode(eventID, hashContainer)
		if bytes.HasPrefix(eventID, prefix) {
			formedRoomID := id.RoomID(fmt.Sprintf("!%s", eventID))
			_, _ = fmt.Fprintln(os.Stderr, "Thread ID", threadID, "iterated over", chunks*chunkSize+i, "hashes in", time.Since(start).String(), "and found", formedRoomID)
			fmt.Println(string(pduJSONWithHashField))

			createContentJSON := gjson.GetBytes(pduJSON, "content").Raw
			roomVersion := gjson.Get(createContentJSON, "room_version").Str
			createContentJSON = exerrors.Must(sjson.Delete(createContentJSON, "room_version"))
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"fi.mau.origin_server_ts": *timestamp,
				"fi.mau.room_id":          formedRoomID,
				"creation_content":        json.RawMessage(createContentJSON),
				"room_version":            roomVersion,
			})
			os.Exit(0)
		}
		if i == chunkSize {
			dur := time.Since(lastChunk)
			_, _ = fmt.Fprintln(os.Stderr, "Thread ID", threadID, "checkpoint", chunks, "checked", chunkSize, "hashes,", (dur / time.Duration(chunkSize)).String(), "per hash")
			i = 0
			chunks++
			lastChunk = time.Now()
			if chunks >= maxChunks {
				_, _ = fmt.Fprintln(os.Stderr, "Thread ID", threadID, "reached maximum chunks of", maxChunks, "after", time.Since(start).String())
				break
			}
		}
		*unsafeRandomnessUint32++
	}
}
