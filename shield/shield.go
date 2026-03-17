package shield

// Set is used to encrypt shield and write to runtime shield stub.
func Set(tpl, shield []byte) ([]byte, error) {
	output := make([]byte, len(tpl))
	copy(output, tpl)
	return output, nil
}

// Get is used to extra shield from tje runtime shield stub.
func Get(instance []byte, offset int) ([]byte, error) {
	return nil, nil
}
