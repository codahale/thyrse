package testdata

// ErrReader is a type that implements the io.Reader interface and always returns an error specified in its Err field.
type ErrReader struct {
	Err error
}

func (e *ErrReader) Read(_ []byte) (n int, err error) {
	return 0, e.Err
}
