// oncedrop: one-shot, end-to-end encrypted file hand-off from this
// machine to a phone anywhere on the internet, via a free tunnel and a QR
// code. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/uetam3/oncedrop/internal/cfbin"
	"github.com/uetam3/oncedrop/internal/server"
	"github.com/uetam3/oncedrop/internal/share"
	"github.com/uetam3/oncedrop/internal/tunnel"
	"github.com/uetam3/oncedrop/web"
)

const defaultAdminAddr = "127.0.0.1:47651"

// version is set at release time with -ldflags "-X main.version=<v>".
var version = "dev"

func main() {
	var (
		provider    = flag.String("tunnel", tunnel.ProviderAuto, "tunnel provider: auto|cloudflared|localhost.run|none")
		idle        = flag.Duration("tunnel-idle", 3*time.Minute, "close the tunnel this long after the panel was closed and no link is pending")
		ttl         = flag.Duration("ttl", 15*time.Minute, "how long a share link stays valid")
		maxSize     = flag.Int64("max-size", 100<<20, "maximum file size in bytes")
		maxTotal    = flag.Int64("max-total", 1<<30, "maximum bytes held in memory across all shares")
		maxShares   = flag.Int("max-shares", 50, "maximum number of shares kept at once")
		adminAddr   = flag.String("admin", defaultAdminAddr, "local admin panel listen address (loopback only)")
		publicAddr  = flag.String("public", "127.0.0.1:0", "local address the tunnel forwards to")
		secretFile  = flag.String("secret-file", defaultSecretFile(), "file holding the admin panel key (created if missing)")
		noOpen      = flag.Bool("no-open", false, "do not open the admin panel in a browser")
		noQR        = flag.Bool("no-qr", false, "do not print QR codes in the terminal")
		insecureHK  = flag.Bool("insecure-hostkey", false, "skip localhost.run host key pinning")
		showVersion = flag.Bool("version", false, "print version information and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] [file ...]\n\n"+
			"Runs the local panel and shares each file once. The tunnel opens only\n"+
			"while the panel is open or a link is waiting to be downloaded.\n"+
			"If an instance is already running, files are handed to it.\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		cf := cfbin.Version()
		if cf == "" {
			cf = "not embedded"
		}
		fmt.Printf("oncedrop %s %s/%s, cloudflared %s\n", version, runtime.GOOS, runtime.GOARCH, cf)
		return
	}
	if !tunnel.ValidProvider(*provider) {
		fmt.Fprintf(os.Stderr, "unknown -tunnel %q\n", *provider)
		os.Exit(2)
	}
	tunnel.AllowUnknownHostKey = *insecureHK

	logger := log.New(os.Stderr, "", log.Ltime)
	log.SetFlags(log.Ltime)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := requireLoopback(*adminAddr); err != nil {
		logger.Fatalf("-admin: %v", err)
	}
	secret, err := loadSecret(*secretFile)
	if err != nil {
		logger.Fatalf("admin key: %v", err)
	}

	admLn, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		// Most likely oncedrop is already running: hand over to it.
		if running, cerr := checkInstance(*adminAddr, secret); running {
			if cerr != nil {
				logger.Fatal(cerr)
			}
			if err := handOver(ctx, *adminAddr, secret, flag.Args(), *ttl, !*noQR, !*noOpen); err != nil {
				logger.Fatal(err)
			}
			return
		}
		logger.Fatalf("admin listen: %v (use -admin 127.0.0.1:0 for a random port)", err)
	}
	admHost := admLn.Addr().String()

	// Public listener (tunnel target). Bound to loopback; only the tunnel
	// process/connection reaches it.
	pubLn, err := net.Listen("tcp", *publicAddr)
	if err != nil {
		logger.Fatalf("public listen: %v", err)
	}
	pubPort := pubLn.Addr().(*net.TCPAddr).Port

	dist := web.Dist()
	store := share.NewStore()
	store.MaxBytes, store.MaxShares = *maxTotal, *maxShares

	var tun *tunnel.Manager
	public := server.NewPublic(store, dist, logger, func() string { return tun.Status().Provider })
	public.OnDownload = func(sh *share.Share) {
		fmt.Printf("\n✔ %s downloaded (%s). The link is now dead.\n", sh.Header.Name, sh.RemoteAddr)
	}
	tun = &tunnel.Manager{
		Provider:  *provider,
		Port:      pubPort,
		Idle:      *idle,
		Log:       logger,
		Hold:      func() bool { return store.HasActive() || public.Busy() },
		ProbePath: server.ProbePath,
	}
	admin := server.NewAdmin(store, tun, dist, logger, admHost, secret, *ttl, *maxSize)

	pubSrv := &http.Server{
		Handler:           public.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Minute, // big file, slow phone
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	admSrv := &http.Server{Handler: admin.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := pubSrv.Serve(pubLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("public server: %v", err)
		}
	}()
	go func() {
		if err := admSrv.Serve(admLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("admin server: %v", err)
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				store.Sweep(10 * time.Minute)
			}
		}
	}()
	tunDone := make(chan struct{})
	go func() {
		tun.Run(ctx)
		close(tunDone)
	}()

	fmt.Printf("Admin panel: %s\n", admin.LoginURL())
	fmt.Printf("The tunnel opens when the panel is open (idle timeout %s).\n", *idle)
	if !*noOpen && len(flag.Args()) == 0 {
		openBrowser(admin.OneTimeLoginURL())
	}

	if len(flag.Args()) > 0 {
		wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := tun.WaitURL(wctx)
		cancel()
		if err != nil {
			logger.Printf("cannot share files: %v", err)
		}
		for _, path := range flag.Args() {
			if err != nil {
				break
			}
			if err := shareFile(admin, store, path, *ttl, *maxSize, !*noQR); err != nil {
				logger.Printf("%s: %v", path, err)
			}
		}
	}

	<-ctx.Done()
	fmt.Println("\nShutting down.")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = pubSrv.Shutdown(shutdownCtx)
	_ = admSrv.Shutdown(shutdownCtx)
	<-tunDone
}

func shareFile(admin *server.Admin, store *share.Store, path string, ttl time.Duration, maxSize int64, printQR bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxSize {
		return fmt.Errorf("file is %d bytes, over -max-size %d", len(data), maxSize)
	}
	name := filepath.Base(path)
	ctype := mime.TypeByExtension(filepath.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	sh, err := store.Create(share.Header{Name: name, Type: ctype}, data, ttl)
	if err != nil {
		return err
	}
	printShare(name, len(data), ttl, admin.ShareURL(sh), printQR)
	return nil
}

func printShare(name string, size int, ttl time.Duration, url string, printQR bool) {
	fmt.Printf("\n%s  (%s, valid %s)\n%s\n", name, humanSize(size), ttl, url)
	if printQR {
		q, err := qrcode.New(url, qrcode.Medium)
		if err == nil {
			fmt.Print(q.ToSmallString(false))
		}
	}
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " KB"
	}
	return strconv.Itoa(n) + " B"
}

// openBrowser is best effort. On WSL it hands the URL to Windows. The URL
// ends up on a command line that other local users can read, so callers pass
// a one-time login link, never the panel key. A variable for tests.
var openBrowser = func(url string) {
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", url)
	case runtime.GOOS == "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case isWSL():
		if _, err := exec.LookPath("wslview"); err == nil {
			cmd = exec.Command("wslview", url)
		} else {
			cmd = exec.Command("cmd.exe", "/c", "start", "", strings.ReplaceAll(url, "&", "^&"))
		}
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func isWSL() bool {
	b, err := os.ReadFile("/proc/version")
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}
