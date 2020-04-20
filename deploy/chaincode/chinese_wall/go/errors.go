package main

import (
    "fmt"
)

type errorType int

const (
	NOTFOUND errorType = iota
	FOUND
)

type chineseWallErr struct {
  arg  int
  prob string
}

func (e *chineseWallErr) Error() string {
    return fmt.Sprintf("%d - %s", e.arg, e.prob)
}
