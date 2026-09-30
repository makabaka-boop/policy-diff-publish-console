// Command policylab 启动“有限域模拟访问策略”演示服务。
//
// 注意：本服务是教学/演示用的模拟沙盒，不是任何真实系统的鉴权入口。
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"

	"policylab/internal/server"
)

//go:embed all:web
var webFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "监听地址")
	flag.Parse()

	srv := server.NewDefault()

	static, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Handler())
	mux.Handle("/", http.FileServerFS(static))

	log.Printf("policylab 模拟策略沙盒已启动: http://localhost%s （仅用于模拟，不是真实鉴权入口）", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
