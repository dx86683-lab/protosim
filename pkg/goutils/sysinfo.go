package goutils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jaypipes/ghw"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HostOSInfo struct {
	Name                 string `json:"name,omitempty"`
	Version              string `json:"version,omitempty"`
	KernelVersion        string `json:"kernelversion,omitempty"`
	Arch                 string `json:"arch,omitempty"`
	Platform             string `json:"platform,omitempty"`
	PlatformFamily       string `json:"platformFamily,omitempty"` // ex: debian, rhel
	VirtualizationSystem string `json:"virtualizationSystem,omitempty"`
	VirtualizationRole   string `json:"virtualizationRole,omitempty"` // guest or host
}

type HostHardwareCPUInfo struct {
	CPU        int32   `json:"cpu,omitempty"`
	VendorID   string  `json:"vendorId,omitempty"`
	Family     string  `json:"family,omitempty"`
	Model      string  `json:"model,omitempty"`
	Stepping   int32   `json:"stepping,omitempty"`
	PhysicalID string  `json:"physicalId,omitempty"`
	CoreID     string  `json:"coreId,omitempty"`
	Cores      int32   `json:"cores,omitempty"`
	ModelName  string  `json:"modelName,omitempty"`
	Mhz        float64 `json:"mhz,omitempty"`
	CacheSize  int32   `json:"cacheSize,omitempty"`
	//Flags      []string `json:"flags,omitempty"`
	Microcode string `json:"microcode,omitempty"`
}

type HostHardwareInfo struct {
	CPUs      []HostHardwareCPUInfo `json:"cpus,omitempty"` //cpu信息
	BIOS      *ghw.BIOSInfo         `json:"bios,omitempty"`
	Memory    []*ghw.MemoryModule   `json:"memory,omitempty"`
	Baseboard *ghw.BaseboardInfo    `json:"baseBoard,omitempty"`
	// memory
	// disk
	// nic
}

type HostSoftwareInfo struct {
}

// NetInterfaceAddr is designed for represent interface addresses
type InterfaceAddr struct {
	Addr string `json:"addr"`
}

type HostNetworkInterfaceInfo struct {
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`          // maximum transmission unit
	Name         string   `json:"name"`         // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr string   `json:"hardwareaddr"` // IEEE MAC-48, EUI-48 and EUI-64 form
	Flags        []string `json:"flags"`        // e.g., FlagUp, FlagLoopback, FlagMulticast
	Addrs        []string `json:"addrs"`
}

// Addr is implemented compatibility to psutil
type Addr struct {
	IP   string `json:"ip,omitempty"`
	Port uint32 `json:"port,omitempty"`
}

type HostNetworkPortInfo struct {
	//Fd     uint32  `json:"fd"`
	//Family string  `json:"family,omitempty"`
	Type   string  `json:"type,omitempty"`
	Laddr  Addr    `json:"localaddr,omitempty"`
	Raddr  *Addr   `json:"remoteaddr,omitempty"`
	Status string  `json:"status,omitempty"`
	Uids   []int32 `json:"uids,omitempty"`
	Pid    int32   `json:"pid,omitempty"`
}

type HostNetworkInfo struct {
	Interfaces []HostNetworkInterfaceInfo `json:"interfaces,omitempty"` //网络接口配置
	Ports      []HostNetworkPortInfo      `json:"ports,omitempty"`      //监听端口信息
}

type HostServiceInfo struct {
}

type HostAutoStartInfo struct {
}

type HostServicesInfo struct {
	SystemServices []HostServiceInfo   `json:"services,omitempty"`
	AutoStarts     []HostAutoStartInfo `json:"autostarts,omitempty"`
}

type HostUserInfo struct {
	User     string `json:"user,omitempty"`
	Terminal string `json:"terminal,omitempty"`
	Host     string `json:"host,omitempty"`
	Started  int    `json:"started,omitempty"`
}

type HostVirtualMemoryInfo struct {
	Total       uint64  `json:"total,omitempty"`
	Available   uint64  `json:"available,omitempty"`
	Used        uint64  `json:"used,omitempty"`
	UsedPercent float64 `json:"usedPercent,omitempty"`
	Free        uint64  `json:"free,omitempty"`
}

type HostDiskPartitionInfo struct {
	Device     string `json:"device,omitempty"`
	Mountpoint string `json:"mountpoint,omitempty"`
	Fstype     string `json:"fstype,omitempty"`
	Opts       string `json:"opts,omitempty"`
}

type HostDiskInfo struct {
	Partitions []HostDiskPartitionInfo `json:"partitions,omitempty"`
}

type HostProcessInfo struct {
	Pid     int32  `json:"pid,omitempty"`
	Name    string `json:"name,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

type HostConnectionInfo struct {
}

type HostSysInfo struct {
	HostID   string           `json:"hostid,omitempty"`   //主机id
	Hostname string           `json:"hostname,omitempty"` //主机名
	Uptime   uint64           `json:"uptime,omitempty"`   //启动时间
	Procs    uint64           `json:"procs,omitempty"`    // 进程数量
	OS       HostOSInfo       `json:"os,omitempty"`       //操作系统信息
	Hardware HostHardwareInfo `json:"hardware,omitempty"` //硬件信息
	//Software []HostSoftwareInfo `json:"software,omitempty"`	//软件信息
	Network HostNetworkInfo `json:"network,omitempty"` //网络信息，与硬件的区别在与：硬件关注硬件属性，这里关注网络配置
	//Services HostServicesInfo `json:"services,omitempty"`	//服务信息，包含系统服务和自启动信息
	Users     []HostUserInfo        `json:"users,omitempty"`     //用户信息
	Memory    HostVirtualMemoryInfo `json:"memory,omitempty"`    //这里是虚拟内存，不对应硬件信息
	Disk      HostDiskInfo          `json:"disks,omitempty"`     //磁盘信息，不对应硬件信息
	Processes []HostProcessInfo     `json:"processes,omitempty"` //进程列表
}

func (info *HostSysInfo) String() string {
	s, _ := json.Marshal(info)
	return string(s)
}

// 运行时间的字符串
func (info *HostSysInfo) UpTimeString() string {
	return (time.Second * time.Duration(info.Uptime)).String()
}

type DarwinMemoryItem struct {
	Name         string `json:"_name,omitempty"`
	Manufacturer string `json:"dimm_manufacturer,omitempty"`
	Size         string `json:"dimm_size,omitempty"`
	Speed        string `json:"dimm_speed,omitempty"`
	Type         string `json:"dimm_type,omitempty"`
}

type DarwinMemoryDataType struct {
	Items []DarwinMemoryItem `json:"_items,omitempty"`
}

/* DarwinMemoryJSON
system_profiler -json SPMemoryDataType
{
  "SPMemoryDataType" : [
    {
      "_items" : [
        {
          "_name" : "BANK 0/ChannelA-DIMM0",
          "dimm_manufacturer" : "SK Hynix",
          "dimm_part_number" : "-",
          "dimm_serial_number" : "-",
          "dimm_size" : "8 GB",
          "dimm_speed" : "2133 MHz",
          "dimm_status" : "ok",
          "dimm_type" : "LPDDR3"
        },
        {
          "_name" : "BANK 2/ChannelB-DIMM0",
          "dimm_manufacturer" : "SK Hynix",
          "dimm_part_number" : "-",
          "dimm_serial_number" : "-",
          "dimm_size" : "8 GB",
          "dimm_speed" : "2133 MHz",
          "dimm_status" : "ok",
          "dimm_type" : "LPDDR3"
        }
      ],
      "_name" : "global_name",
      "global_ecc_state" : "ecc_disabled",
      "is_memory_upgradeable" : "No"
    }
  ]
}
*/
type DarwinMemoryJSON struct {
	SPMemoryDataType []DarwinMemoryDataType
}

// run wraps `exec.Command` with easy access to stdout and stderr.
func run(stdout, stderr io.Writer, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

func trim(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\n"))
}

// machineID returns the uuid returned by `ioreg -rd1 -c IOPlatformExpertDevice`.
// If there is an error running the commad an empty string is returned.
func machineID() (string, error) {
	buf := &bytes.Buffer{}
	err := run(buf, os.Stderr, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	id, err := extractID(buf.String())
	if err != nil {
		return "", err
	}
	return trim(id), nil
}

func extractID(lines string) (string, error) {
	for _, line := range strings.Split(lines, "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitAfter(line, `" = "`)
			if len(parts) == 2 {
				return strings.TrimRight(parts[1], `"`), nil
			}
		}
	}
	return "", fmt.Errorf("Failed to extract 'IOPlatformUUID' value from `ioreg` output.\n%s", lines)
}

func GetMarchineID() string {
	if info, err := host.Info(); err == nil {
		hostid := info.HostID
		if runtime.GOOS == "darwin" {
			if id, err := machineID(); err == nil {
				hostid += ":" + id
			}
		}
		hash := md5.Sum([]byte("go" + hostid + "by"))
		return hex.EncodeToString(hash[:])
	}
	return ""
}

func GetSysInfo(withProcess bool) *HostSysInfo {
	r := &HostSysInfo{}

	if info, err := host.Info(); err == nil {
		r.HostID = info.HostID
		r.Hostname = info.Hostname
		r.Uptime = info.Uptime
		r.Procs = info.Procs
		r.OS = HostOSInfo{
			Name:                 info.OS,
			Version:              info.PlatformVersion,
			Arch:                 info.KernelArch,
			Platform:             info.Platform,
			PlatformFamily:       info.PlatformFamily,
			KernelVersion:        info.KernelVersion,
			VirtualizationSystem: info.VirtualizationSystem,
			VirtualizationRole:   info.VirtualizationRole,
		}
	}

	if info, err := host.Users(); err == nil {
		for _, user := range info {
			r.Users = append(r.Users, HostUserInfo{
				User:     user.User,
				Terminal: user.Terminal,
				Host:     user.Host,
				Started:  user.Started,
			})
		}
	}

	if info, err := cpu.Info(); err == nil {
		for _, cpu := range info {
			r.Hardware.CPUs = append(r.Hardware.CPUs, HostHardwareCPUInfo{
				CPU:        cpu.CPU,
				VendorID:   cpu.VendorID,
				Family:     cpu.Family,
				Model:      cpu.Model,
				Stepping:   cpu.Stepping,
				PhysicalID: cpu.PhysicalID,
				CoreID:     cpu.CoreID,
				Cores:      cpu.CPU,
				ModelName:  cpu.ModelName,
				Mhz:        cpu.Mhz,
				CacheSize:  cpu.CacheSize,
				//Flags: cpu.Flags,
				Microcode: cpu.Microcode,
			})
		}
	}

	if info, err := mem.VirtualMemory(); err == nil {
		r.Memory = HostVirtualMemoryInfo{
			Total:       info.Total,
			Available:   info.Available,
			Used:        info.Used,
			UsedPercent: info.UsedPercent,
		}
	} else {
		log.Println("[WARNING] fetch memory failed:", err)
	}

	if info, err := disk.Partitions(false); err == nil {
		for _, partition := range info {
			r.Disk.Partitions = append(r.Disk.Partitions, HostDiskPartitionInfo{
				Device:     partition.Device,
				Mountpoint: partition.Mountpoint,
				Fstype:     partition.Fstype,
				Opts:       partition.Opts,
			})
		}
	} else {
		log.Println("[WARNING] fetch disk failed:", err)
	}

	// 比较耗时
	if withProcess {
		if info, err := process.Processes(); err == nil {
			for _, proc := range info {
				pi := HostProcessInfo{
					Pid: proc.Pid,
				}
				if v, err := proc.Name(); err == nil {
					pi.Name = v
				}
				if v, err := proc.Cmdline(); err == nil {
					pi.Cmdline = v
				}
				r.Processes = append(r.Processes, pi)
			}
		}
	}

	if info, err := net.Interfaces(); err == nil {
		for _, nic := range info {
			var addrStrings []string
			for _, addr := range nic.Addrs {
				addrStrings = append(addrStrings, addr.Addr)
			}
			r.Network.Interfaces = append(r.Network.Interfaces, HostNetworkInterfaceInfo{
				Index:        nic.Index,
				MTU:          nic.MTU,
				Name:         nic.Name,
				HardwareAddr: nic.HardwareAddr,
				Flags:        nic.Flags,
				Addrs:        addrStrings,
			})
		}
	}

	if info, err := net.Connections("all"); err == nil {
		for _, port := range info {
			family := ""
			switch port.Family {
			case syscall.AF_INET:
				family = ""
			case syscall.AF_INET6:
				family = "6"
			}
			ptype := ""
			switch port.Type {
			case syscall.SOCK_STREAM:
				ptype = "tcp"
			case syscall.SOCK_DGRAM:
				ptype = "udp"
			}
			var raddr *Addr
			if port.Raddr.Port > 0 {
				raddr = &Addr{
					IP:   port.Raddr.IP,
					Port: port.Raddr.Port,
				}
			}
			r.Network.Ports = append(r.Network.Ports, HostNetworkPortInfo{
				Pid: port.Pid,
				//Fd: port.Fd,
				//Family: family,
				Type:   ptype + family,
				Status: port.Status,
				Uids:   port.Uids,
				Laddr: Addr{
					IP:   port.Laddr.IP,
					Port: port.Laddr.Port,
				},
				Raddr: raddr,
			})
		}
	} else {
		log.Println("[WARNING] fetch connections failed:", err)
	}

	if info, err := ghw.BIOS(); err == nil {
		r.Hardware.BIOS = info
	} else {
		log.Println("[WARNING] fetch BIOS failed:", err)
	}

	if info, err := ghw.Memory(); err == nil {
		r.Hardware.Memory = info.Modules
	} else {
		if runtime.GOOS == "darwin" {
			var v []byte
			v, err = exec.Command("system_profiler", "-json", "SPMemoryDataType").Output()
			if err == nil {
				var d DarwinMemoryJSON
				if err = json.Unmarshal(v, &d); err == nil {
					for _, item := range d.SPMemoryDataType {
						for _, memory := range item.Items {
							var size int64 = 0
							s := strings.Split(memory.Size, " ")
							if s[1] == "GB" {
								gb, _ := strconv.Atoi(s[0])
								size = int64(gb * 1024 * 1024 * 1024)
							}
							r.Hardware.Memory = append(r.Hardware.Memory, &ghw.MemoryModule{
								Vendor:    memory.Manufacturer,
								Location:  memory.Name,
								SizeBytes: size,
							})
						}
					}
				}
			}
		}
		if err != nil {
			log.Println("[WARNING] fetch Memory failed:", err)
		}
	}

	if info, err := ghw.Baseboard(); err == nil {
		r.Hardware.Baseboard = info
	} else {
		log.Println("[WARNING] fetch Baseboard failed:", err)
	}

	return r
}
