package main

import "testing"

// Test operations on a zero-capacity stack.
func TestZeroCapacity(t *testing.T) {
	var ok bool

	s := NewStack(0)
	if s.Length() != 0 {
		t.Fatal("initial length is not 0")
	}
	_, ok = s.Push("a")
	if ok || s.Length() != 0 {
		t.Fatal()
	}
	_, ok = s.Pop()
	if ok || s.Length() != 0 {
		t.Fatal()
	}
}

func TestPushPop(t *testing.T) {
	var x interface{}
	var ok bool

	s := NewStack(3)

	// Push elems.
	if s.Length() != 0 {
		t.Fatal("initial length is not 0")
	}
	_, ok = s.Push("a")
	if !ok || s.Length() != 1 {
		t.Fatal()
	}
	_, ok = s.Push("b")
	if !ok || s.Length() != 2 {
		t.Fatal()
	}

	// Pop to empty.
	x, ok = s.Pop()
	if !ok || x != "b" || s.Length() != 1 {
		t.Fatal()
	}
	x, ok = s.Pop()
	if !ok || x != "a" || s.Length() != 0 {
		t.Fatal()
	}
	// Pop one past empty.
	x, ok = s.Pop()
	if ok {
		t.Fatal()
	}

	// Push to capacity.
	s.Push("c")
	s.Push("d")
	_, ok = s.Push("e")
	if !ok || s.Length() != 3 {
		t.Fatal("push to capacity is not at capacity")
	}
	// Push one past capacity.
	x, ok = s.Push("f")
	if ok || s.Length() != 3 {
		t.Fatal()
	}
	if x != "c" {
		t.Fatal("mismatch in overwritten element")
	}

	// Pop to empty.
	x, ok = s.Pop()
	if !ok || x != "f" || s.Length() != 2 {
		t.Fatal()
	}
	x, ok = s.Pop()
	if !ok || x != "e" || s.Length() != 1 {
		t.Fatal()
	}
	x, ok = s.Pop()
	if !ok || x != "d" || s.Length() != 0 {
		t.Fatal()
	}
	// Pop one past empty.
	x, ok = s.Pop()
	if ok {
		t.Fatal()
	}
}

// Test underflow of an initially empty stack.
func TestUnderflowEmpty(t *testing.T) {
	var ok bool

	s := NewStack(3)
	_, ok = s.Pop()
	if ok {
		t.Fatal()
	}
}

// Test underflow of a stack that had been full.
func TestUnderflowFull(t *testing.T) {
	var ok bool

	s := NewStack(3)
	s.Push("a")
	s.Push("b")
	s.Push("c")
	s.Push("d")
	s.Pop()
	s.Pop()
	s.Pop()
	_, ok = s.Pop()
	if ok {
		t.Fatal()
	}
}
