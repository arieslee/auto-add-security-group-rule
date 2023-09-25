package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
)

var JsonFile = "./cfg.json"

var GroupRule = &sGroupRule{
	Cmd: &GroupRuleCMD{},
}

type GroupRuleCMD struct {
	Ip           string `json:"ip"`
	StartPort    string `json:"start_port"`
	EndPort      string `json:"end_port"`
	AccessSecret string `json:"access_secret"`
	AccessKeyId  string `json:"access_key_id"`
	RegionId     string `json:"region_id"`
	GroupId      string `json:"group_id"`
	Scheme       string `json:"scheme"`
	Protocol     string `json:"protocol"`
	Policy       string `json:"policy"`
	NicType      string `json:"nic_type"`
	Description  string `json:"description"`
}
type sGroupRule struct {
	Cmd *GroupRuleCMD `json:"cmd"`
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
func (s *sGroupRule) Input(ctx context.Context) error {
	s.Cmd.Ip = gcmd.Scan("Please input your ip(defaults to the current public ip):\n")
	s.Cmd.StartPort = gcmd.Scan("Please input startPort:\n")
	if s.Cmd.StartPort == "" {
		return errors.New("startPort cant be empty")
	}
	s.Cmd.EndPort = gcmd.Scan("Please input endPort:\n")
	if s.Cmd.EndPort == "" {
		s.Cmd.EndPort = s.Cmd.StartPort
	}
	s.Cmd.AccessKeyId = gcmd.Scan("Please input your accessKeyId:\n")
	if s.Cmd.AccessKeyId == "" {
		return errors.New("accessKeyId cant be empty")
	}
	s.Cmd.AccessSecret = gcmd.Scan("Please input your accessSecret:\n")
	if s.Cmd.AccessSecret == "" {
		return errors.New("accessSecret cant be empty")
	}
	s.Cmd.RegionId = gcmd.Scan("Please input regionId(e.g. cn-beijing):\n")
	if s.Cmd.RegionId == "" {
		return errors.New("regionId cant be empty")
	}
	s.Cmd.GroupId = gcmd.Scan("Please input groupId:\n")
	if s.Cmd.GroupId == "" {
		return errors.New("groupId cant be empty")
	}
	s.Cmd.Scheme = gcmd.Scan("Please input scheme(default https):\n")
	if s.Cmd.Scheme == "" {
		s.Cmd.Scheme = "https"
	}
	s.Cmd.Protocol = gcmd.Scan("Please input protocol(default tcp):\n")
	if s.Cmd.Protocol == "" {
		s.Cmd.Protocol = "tcp"
	}
	s.Cmd.Policy = gcmd.Scan("Please input policy(default accept. options: accept、drop):\n")
	if s.Cmd.Protocol == "" {
		s.Cmd.Protocol = "accept"
	}
	s.Cmd.NicType = gcmd.Scan("Please input nicType(default internet. options: internet、intranet):\n")
	if s.Cmd.NicType == "" {
		s.Cmd.NicType = "internet"
	}
	s.Cmd.Description = gcmd.Scan("Please input description(allow empty):\n")
	if s.Cmd.Description == "" {
		s.Cmd.Description = gtime.Now().Format("Y-m-d H:i:s added rule")
	}
	jsonStr, _ := gjson.EncodeString(s.Cmd)
	gfile.PutContents(JsonFile, jsonStr)
	return nil
}
func (s *sGroupRule) ParseCmd(ctx context.Context) error {
	var loadPrev string
	if gfile.Exists(JsonFile) {
		loadPrev = gcmd.Scan("Whether there is no more last configuration?(Y/n)")
		if loadPrev == "Y" {
			s.Cmd = &GroupRuleCMD{}
			data := gfile.GetContents(JsonFile)
			gconv.Scan(data, &s.Cmd)
		} else {
			s.Input(ctx)
		}
	} else {
		s.Input(ctx)
	}
	return nil
}

func (s *sGroupRule) Add(ctx context.Context) {
	err := s.ParseCmd(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	clientIP := s.Cmd.Ip
	if clientIP == "" {
		clientIP, err = s.GetIp(ctx)
		if err != nil {
			fmt.Print(err.Error())
			return
		}
	}
	client, err := ecs.NewClientWithAccessKey(s.Cmd.RegionId, s.Cmd.AccessKeyId, s.Cmd.AccessSecret)
	if err != nil {
		fmt.Print(err.Error())
	}
	request := ecs.CreateAuthorizeSecurityGroupRequest()
	request.Scheme = s.Cmd.Scheme
	request.SecurityGroupId = s.Cmd.GroupId                   // 安全组ID
	request.IpProtocol = s.Cmd.Protocol                       // 协议,可选 tcp,udp, icmp, gre, all：支持所有协议
	request.PortRange = s.Cmd.StartPort + "/" + s.Cmd.EndPort // 端口范围，使用斜线（/）隔开起始端口和终止端口
	request.Priority = "1"                                    // 安全组规则优先级，数字越小，代表优先级越高。取值范围：1~100
	request.Policy = s.Cmd.Policy                             // accept:接受访问, drop: 拒绝访问
	request.NicType = s.Cmd.NicType                           // internet：公网网卡, intranet：内网网卡。
	request.SourceCidrIp = clientIP                           // 源端IPv4 CIDR地址段。支持CIDR格式和IPv4格式的IP地址范围。
	request.Description = s.Cmd.Description

	response, err := client.AuthorizeSecurityGroup(request)
	if err != nil {
		fmt.Print(err.Error())
		return
	}
	fmt.Printf("Response: %#v\nClient IP: %s  was successfully added to the Security Group.\n", response, clientIP)
}
