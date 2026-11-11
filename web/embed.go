// Package web embeds the built Preact frontend (run `npm run build` in web/).
// web/dist is not committed: without a build only dist/.keep is embedded and
// the pages answer "frontend not built".
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist is the built frontend rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
