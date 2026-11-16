package socket_test

import "sync"

// errGroup runs functions on goroutines and reports the first error any of
// them returns, as the tests only need that much of x/sync/errgroup.
type errGroup struct {
	wg   sync.WaitGroup
	once sync.Once
	err  error
}

// Go runs f on a new goroutine.
func (g *errGroup) Go(f func() error) {
	g.wg.Go(func() {
		if err := f(); err != nil {
			g.once.Do(func() { g.err = err })
		}
	})
}

// Wait blocks until every function started with Go has returned, then returns
// the first non-nil error.
func (g *errGroup) Wait() error {
	g.wg.Wait()
	return g.err
}
