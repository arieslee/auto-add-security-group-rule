package main

import (
	"auto-add-security-group-rule/internal/service"
	"github.com/gogf/gf/v2/os/gctx"
)

func main() {
	ctx := gctx.GetInitCtx()
	service.GroupRule.Add(ctx)
}
