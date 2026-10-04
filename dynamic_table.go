package qpack

// dynamicTable is the QPACK dynamic table (RFC 9204, Section 3.2).
// Entries are stored in a ring buffer, oldest first. Absolute indices are
// zero-based: the first entry ever inserted has absolute index 0, and
// evictions do not change the absolute indices of the remaining entries.
type dynamicTable struct {
	entries []dynamicTableEntry

	// head is the position of the oldest entry still present.
	head int
	// size is the number of entries currently present.
	size int

	// tableSize is the sum of the dynamic table sizes of all present entries.
	tableSize uint64
	// capacity is the current dynamic table capacity.
	capacity uint64

	// knownReceivedCount is the total number of entries inserted so far
	// (including entries that have since been evicted).
	knownReceivedCount uint64

	// smallestAbsoluteIndex is the absolute index of the oldest present entry,
	// or knownReceivedCount if the table is empty (or has never held entries).
	smallestAbsoluteIndex uint64
}

type dynamicTableEntry struct {
	Name  string
	Value string
	size  uint64
}

func dynamicEntrySize(name, value string) uint64 {
	return uint64(len(name)) + uint64(len(value)) + 32
}

// setCapacity changes the dynamic table capacity, evicting the oldest entries
// until the remaining entries fit. It does not change the absolute indices of
// the surviving entries.
func (t *dynamicTable) setCapacity(c uint64) {
	t.capacity = c
	t.evict()
}

func (t *dynamicTable) evict() {
	for t.tableSize > t.capacity && t.size > 0 {
		oldest := t.entries[t.head]
		t.tableSize -= oldest.size
		t.head = (t.head + 1) % len(t.entries)
		t.size--
		t.smallestAbsoluteIndex++
	}
}

// add inserts a new entry, evicting the oldest entries as necessary.
// It is the caller's responsibility to make sure the entry fits into the
// current capacity. It returns the absolute index of the new entry.
func (t *dynamicTable) add(name, value string) uint64 {
	e := dynamicTableEntry{Name: name, Value: value, size: dynamicEntrySize(name, value)}
	if t.size == len(t.entries) {
		t.grow()
	}
	idx := (t.head + t.size) % len(t.entries)
	t.entries[idx] = e
	t.size++
	t.tableSize += e.size
	absoluteIndex := t.knownReceivedCount
	t.knownReceivedCount++
	t.evict()
	return absoluteIndex
}

func (t *dynamicTable) grow() {
	newEntries := make([]dynamicTableEntry, max(2*len(t.entries), 2))
	for i := range t.size {
		newEntries[i] = t.entries[(t.head+i)%len(t.entries)]
	}
	t.entries = newEntries
	t.head = 0
}

// at returns the entry with the given absolute index.
func (t *dynamicTable) at(absoluteIndex uint64) (dynamicTableEntry, bool) {
	if absoluteIndex < t.smallestAbsoluteIndex {
		return dynamicTableEntry{}, false
	}
	offset := absoluteIndex - t.smallestAbsoluteIndex
	if offset >= uint64(t.size) {
		return dynamicTableEntry{}, false
	}
	return t.entries[(t.head+int(offset))%len(t.entries)], true
}

func (t *dynamicTable) maxEntries() uint64 {
	return t.capacity / 32
}
