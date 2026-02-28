package testdata

// ErrWriter is a type that wraps an error and implements the io.Writer interface to always return the specified error.
type ErrWriter struct {
	Err error
}

func (e *ErrWriter) Write(_ []byte) (n int, err error) {
	return 0, e.Err
}
