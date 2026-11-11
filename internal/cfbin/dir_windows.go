package cfbin

// checkPrivateDir is a no-op on Windows: the user cache directory is already
// private to the account via inherited ACLs.
func checkPrivateDir(string) error { return nil }
