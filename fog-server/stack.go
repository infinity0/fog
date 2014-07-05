package main

import "sync"

// A fixed-size stack. If a push exceeds the capacity of the underlying slice,
// the least recently added element is lost.
type Stack struct {
	buf        []interface{}
	base, head int
	m          sync.Mutex
}

// Create a stack with the given capacity.
func NewStack(capacity int) *Stack {
	return &Stack{buf: make([]interface{}, capacity+1)}
}

func (s *Stack) clamp(x int) int {
	x = x % len(s.buf)
	if x < 0 {
		x += len(s.buf)
	}
	return x
}

func (s *Stack) Length() int {
	s.m.Lock()
	defer s.m.Unlock()
	return s.clamp(s.head - s.base)
}

// If this push causes the stack to overflow, the first return value is the
// discarded element and the second return value is false. Otherwise the second
// return value is true.
func (s *Stack) Push(x interface{}) (interface{}, bool) {
	s.m.Lock()
	defer s.m.Unlock()
	s.buf[s.head] = x
	s.head = s.clamp(s.head + 1)
	if s.head == s.base {
		s.base = s.clamp(s.base + 1)
		return s.buf[s.head], false
	}
	return nil, true
}

// The second return value is false if the stack was empty, and true otherwise.
// The first return value is defined only when the second is true.
func (s *Stack) Pop() (interface{}, bool) {
	s.m.Lock()
	defer s.m.Unlock()
	if s.head == s.base {
		return nil, false
	}
	s.head = s.clamp(s.head - 1)
	return s.buf[s.head], true
}
