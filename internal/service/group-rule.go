package service

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/gogf/gf/v2/text/gstr"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

var GroupRule = &sGroupRule{}

type sGroupRule struct {
}

func (s *sGroupRule) GetIp(ctx context.Context) (string, error) {
	resp, err := g.Client().Get(ctx, "https://4.ipw.cn/")
	if err != nil {
		return "", fmt.Errorf("获取外网 IP 失败，请检查网络,err=%s", err.Error())
	}
	defer resp.Close()
	ip := resp.ReadAllString()
	return ip, nil
}
func (s *sGroupRule) ParseCmd(ctx context.Context) (*gcmd.Parser, error) {
	return gcmd.Parse(g.MapStrBool{
		"-ip,--ip":           true,
		"-pr,--portRange":    true,
		"-as,--accessSecret": true,
		"-ak,--accessKey":    true,
		"-r,--regionId":      true,
		"-g,--groupId":       true,
		"-s,--scheme":        true,
		"-p,--protocol":      true,
	})
}

func (s *sGroupRule) Add(ctx context.Context) {
	var (
		regionId     string
		accessKeyId  string
		accessSecret string
		groupId      string
		clientIP     string
		portRange    string
		scheme       string
		protocol     string
	)
	parser, err := s.ParseCmd(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	portRange = parser.GetOpt("portRange").String()
	g.Dump(portRange)
	if !gstr.Contains(portRange, "/") {
		fmt.Println("Invalid port range, it should be like xxx/xxx")
		return
	}
	arr := gstr.SplitAndTrim("/", portRange)
	g.Dump(portRange, len(arr))
	if len(arr) != 2 {
		fmt.Println("Error port range, it should be like xxx/xxx")
		return
	}
	clientIP = parser.GetOpt("ip").String()
	if clientIP == "" {
		clientIP, err = s.GetIp(ctx)
		if err != nil {
			fmt.Print(err.Error())
			return
		}
	}
	regionId = parser.GetOpt("r").String()
	if regionId == "" {
		reg, err := g.Cfg().Get(ctx, "aliyun.regionId")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		regionId = reg.String()
	}
	accessKeyId = parser.GetOpt("ak").String()
	if accessKeyId == "" {
		key, err := g.Cfg().Get(ctx, "aliyun.accessKeyId")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		accessKeyId = key.String()
	}
	accessSecret = parser.GetOpt("as").String()
	if accessSecret == "" {
		secret, err := g.Cfg().Get(ctx, "aliyun.accessSecret")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		accessSecret = secret.String()
	}
	client, err := ecs.NewClientWithAccessKey(regionId, accessKeyId, accessSecret)
	if err != nil {
		fmt.Print(err.Error())
	}
	groupId = parser.GetOpt("g").String()
	if groupId == "" {
		gid, err := g.Cfg().Get(ctx, "aliyun.groupId")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		groupId = gid.String()
	}
	scheme = parser.GetOpt("s").String()
	if scheme == "" {
		scheme = "https"
	}
	protocol = parser.GetOpt("p").String()
	if protocol == "" {
		protocol = "tcp"
	}
	request := ecs.CreateAuthorizeSecurityGroupRequest()
	request.Scheme = scheme
	request.SecurityGroupId = groupId // 安全组ID
	request.IpProtocol = protocol     // 协议,可选 tcp,udp, icmp, gre, all：支持所有协议
	request.PortRange = portRange     // 端口范围，使用斜线（/）隔开起始端口和终止端口
	request.Priority = "1"            // 安全组规则优先级，数字越小，代表优先级越高。取值范围：1~100
	request.Policy = "accept"         // accept:接受访问, drop: 拒绝访问
	request.NicType = "internet"      // internet：公网网卡, intranet：内网网卡。
	request.SourceCidrIp = clientIP   // 源端IPv4 CIDR地址段。支持CIDR格式和IPv4格式的IP地址范围。

	response, err := client.AuthorizeSecurityGroup(request)
	if err != nil {
		fmt.Print(err.Error())
		return
	}
	fmt.Printf("Response: %#v\nClient IP: %s  was successfully added to the Security Group.\n", response, clientIP)
}
