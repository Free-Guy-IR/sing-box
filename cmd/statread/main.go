package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sagernet/sing-box/experimental/v2rayapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// statread <host:port> <counter-name>...  queries sing-box's v2ray_api StatsService.
// sing-box renames the service to the classic v2ray name at runtime (stats.go),
// so we invoke that full method path directly with the generated message types.
func main() {
	conn, err := grpc.NewClient("passthrough:///"+os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("dial err:", err)
		os.Exit(1)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, name := range os.Args[2:] {
		req := &v2rayapi.GetStatsRequest{Name: name}
		resp := &v2rayapi.GetStatsResponse{}
		if err := conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/GetStats", req, resp); err != nil {
			fmt.Printf("%s = ERR %v\n", name, err)
			continue
		}
		if resp.GetStat() == nil {
			fmt.Printf("%s = 0\n", name)
			continue
		}
		fmt.Printf("%s = %d\n", resp.GetStat().GetName(), resp.GetStat().GetValue())
	}
}
