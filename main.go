package main

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: cnet <IP_or_IP/Prefix> [Mask_or_Prefix] [Subnet_Prefix]")
		return
	}

	var ips, maskOrPrefixs, submaskOrPrefixs string

	if len(os.Args) == 2 {
		ips = os.Args[1]
		submaskOrPrefixs = ""
	} else if len(os.Args) == 3 {
		ips = os.Args[1]
		if strings.Contains(ips, "/") {
			parts := strings.Split(ips, "/")
			if len(parts) != 2 {
				return
			}
			ips = parts[0]
			maskOrPrefixs = parts[1]
			submaskOrPrefixs = os.Args[2]
		} else {
			ips = os.Args[1]
			maskOrPrefixs = os.Args[2]
			submaskOrPrefixs = ""
		}
	} else if len(os.Args) == 4 {
		ips = os.Args[1]
		maskOrPrefixs = os.Args[2]
		submaskOrPrefixs = os.Args[3]
	} else {
		fmt.Println("Invalid number of arguments.")
		return
	}

	err := cnet(ips, maskOrPrefixs, submaskOrPrefixs)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func ConvertSubnetMask(mask string) (string, int, error) {

	if regexp.MustCompile(`^\d+$`).MatchString(mask) {
		bits, err := strconv.Atoi(mask)
		if err != nil {
			return "", 0, fmt.Errorf("invalid prefix length: %w", err)
		}
		if bits < 0 || bits > 32 {
			return "", 0, fmt.Errorf("invalid prefix length. Must be between 0 and 32")
		}
		maskString := strings.Repeat("1", bits) + strings.Repeat("0", 32-bits)
		maskBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			val, err := strconv.ParseUint(maskString[i*8:(i+1)*8], 2, 8)
			if err != nil {
				return "", 0, fmt.Errorf("failed to convert binary substring to byte: %w", err)
			}
			maskBytes[i] = byte(val)
		}

		ip := net.IPv4(maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3])
		return ip.String(), bits, nil
	}

	if regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`).MatchString(mask) {
		ip := net.ParseIP(mask)
		if ip == nil {
			return "", 0, fmt.Errorf("invalid IP address format")
		}
		maskBytes := ip.To4()
		if maskBytes == nil {
			return "", 0, fmt.Errorf("invalid IPv4 address")
		}
		var binaryStr strings.Builder
		for _, b := range maskBytes {
			binaryStr.WriteString(fmt.Sprintf("%08b", b))
		}
		if !regexp.MustCompile(`^1*0*$`).MatchString(binaryStr.String()) {
			return "", 0, fmt.Errorf("mask is not in the correct format, please check")
		}
		prefix := len(regexp.MustCompile(`1+`).FindString(binaryStr.String()))
		return mask, prefix, nil
	}

	return "", 0, fmt.Errorf("invalid subnet mask format")
}
func ConvertSubnetMask6(mask string, isIPv6 bool) (string, int, error) {
	if regexp.MustCompile(`^\d+$`).MatchString(mask) {
		bits, err := strconv.Atoi(mask)
		if err != nil {
			return "", 0, fmt.Errorf("invalid prefix length: %w", err)
		}
		if bits < 0 || bits > 128 {
			return "", 0, fmt.Errorf("invalid prefix length. Must be between 0 and 128")
		}
		maskBytes := make([]byte, 16)
		fullBytes := bits / 8
		remainingBits := bits % 8

		for i := 0; i < fullBytes; i++ {
			maskBytes[i] = 0xFF
		}

		if remainingBits > 0 && fullBytes < 16 {
			maskBytes[fullBytes] = byte((0xFF << (8 - remainingBits)) & 0xFF)
		}
		ip := net.IP(maskBytes)
		return ip.String(), bits, nil
	}
	return "", 0, fmt.Errorf("invalid IPv6 subnet mask format")
}
func GetNetworkClass(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid IP address format")
	}
	firstOctet, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid IP address format")
	}

	switch {
	case firstOctet >= 0 && firstOctet <= 127:
		return "A", nil
	case firstOctet >= 128 && firstOctet <= 191:
		return "B", nil
	case firstOctet >= 192 && firstOctet <= 223:
		return "C", nil
	case firstOctet >= 224 && firstOctet <= 239:
		return "D", nil
	case firstOctet >= 240 && firstOctet <= 255:
		return "E", nil
	default:
		return "", fmt.Errorf("invalid IP address format")
	}
}

func cnet(ips, maskOrPrefixs, submaskOrPrefixs string) error {
	var ip, maskOrPrefix, submaskOrPrefix string
	if ips != "" && maskOrPrefixs != "" {
		ip = ips
		maskOrPrefix = maskOrPrefixs
	} else if strings.Contains(ips, "/") {
		parts := strings.Split(ips, "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid IP address format")
		}
		ip = parts[0]
		maskOrPrefix = parts[1]
	} else {
		return fmt.Errorf("invalid IP address format")
	}

	ip = regexp.MustCompile(`[^a-zA-Z0-9.:]`).ReplaceAllString(ip, "")
	maskOrPrefix = regexp.MustCompile(`[^0-9.:]`).ReplaceAllString(maskOrPrefix, "")
	submaskOrPrefix = regexp.MustCompile(`[^0-9.:]`).ReplaceAllString(submaskOrPrefixs, "")

	if strings.Contains(ip, ":") {
		// 处理 IPv6
		prefix, err := strconv.Atoi(maskOrPrefix)
		if err != nil || prefix < 0 || prefix > 128 {
			return fmt.Errorf("invalid IPv6 prefix length (0-128)")
		}
		maskAddress, _, err := ConvertSubnetMask6(maskOrPrefix, true)
		if err != nil {
			return fmt.Errorf("failed to convert mask: %w", err)
		}
		maskBytes := net.ParseIP(maskAddress).To16()
		ipAddress := net.ParseIP(ip)
		if ipAddress == nil {
			return fmt.Errorf("invalid IPv6 address")
		}
		ipBytes := ipAddress.To16()

		networkBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			networkBytes[i] = ipBytes[i] & maskBytes[i]
		}

		networkAddress := net.IP(networkBytes).String()
		networkBigInt := big.NewInt(0).SetBytes(networkBytes)
		maxBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			maxBytes[i] = networkBytes[i] | (^maskBytes[i] & 0xFF)
		}
		maxAddress := net.IP(maxBytes).String()
		availQua := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(128-int64(prefix)), nil)
		if prefix < 127 {
			availQua = availQua.Sub(availQua, big.NewInt(2))
		}

		fmt.Println("---------sub calc (IPv6)---------")
		fmt.Println("IPv6地址         :", ip)
		fmt.Println("网络~最大地址    :", networkAddress, "~", maxAddress)
		fmt.Println("前缀长度         :", prefix)
		fmt.Println("可用地址数量     :", availQua.String())

		if submaskOrPrefix != "" {
			subPrefix, err := strconv.Atoi(submaskOrPrefix)
			if err != nil || subPrefix < 0 || subPrefix > 128 {
				return fmt.Errorf("invalid IPv6 sub prefix length (0-128)")
			}
			if subPrefix > prefix {
				fmt.Println("\n---------DivSubnet---------")
				numSubnets := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(subPrefix-prefix)), nil)
				fmt.Printf("划分 %v 个 %d 子网:\n", numSubnets, subPrefix)

				subnetMaskBytes := make([]byte, 16)
				fullBytes := subPrefix / 8
				remainingBits := subPrefix % 8
				for i := 0; i < fullBytes; i++ {
					subnetMaskBytes[i] = 0xFF
				}
				if remainingBits > 0 && fullBytes < 16 {
					subnetMaskBytes[fullBytes] = byte((0xFF << (8 - remainingBits)) & 0xFF)
				}

				for i := big.NewInt(0); i.Cmp(numSubnets) < 0; i.Add(i, big.NewInt(1)) {
					offset := big.NewInt(0).Lsh(big.NewInt(1), uint(128-subPrefix))
					offset.Mul(offset, i)

					newNetworkBigInt := big.NewInt(0).Add(networkBigInt, offset)
					newNetworkBytes := newNetworkBigInt.Bytes()
					padding := make([]byte, 16-len(newNetworkBytes))
					newNetworkBytes = append(padding, newNetworkBytes...)
					newNetworkAddress := net.IP(newNetworkBytes).String()

					iInt64 := i.Int64()
					if (iInt64 == 3) && (numSubnets.Cmp(big.NewInt(4)) != 0) {
						i = i.SetInt64(numSubnets.Int64() - 4)
						iInt64 = i.Int64() // 更新 iInt64
					}
					if (iInt64 < 3) || (iInt64 > numSubnets.Int64()-4) {
						subnetMaxBytes := make([]byte, 16)
						for j := 0; j < 16; j++ {
							subnetMaxBytes[j] = newNetworkBytes[j] | (^subnetMaskBytes[j] & 0xFF)
						}
						subnetMaxAddress := net.IP(subnetMaxBytes).String()
						fmt.Printf("子网 %d: %s ~ %s\n", iInt64+1, newNetworkAddress, subnetMaxAddress)
					}
				}
			}
		}

	} else {
		// 处理 IPv4
		if !regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`).MatchString(ip) {
			return fmt.Errorf("invalid IPv4 address format")
		}
		subnetMask, prefix, err := ConvertSubnetMask(maskOrPrefix)

		if err != nil {
			return fmt.Errorf("failed to convert subnet mask: %w", err)
		}

		var subPrefix int
		var sub1network string
		if submaskOrPrefix != "" {
			sn, sp, err := ConvertSubnetMask(submaskOrPrefix)
			if err != nil {
				return fmt.Errorf("failed to convert subsubnet mask: %w", err)
			}
			subPrefix = sp
			sub1network = sn
		}

		ipAddr := net.ParseIP(ip).To4()
		if ipAddr == nil {
			return fmt.Errorf("invalid IPv4 address")
		}

		maskAddr := net.ParseIP(subnetMask).To4()
		if maskAddr == nil {
			return fmt.Errorf("invalid IPv4 subnet mask")
		}
		ipInt := uint32(ipAddr[0])<<24 | uint32(ipAddr[1])<<16 | uint32(ipAddr[2])<<8 | uint32(ipAddr[3])
		maskInt := uint32(maskAddr[0])<<24 | uint32(maskAddr[1])<<16 | uint32(maskAddr[2])<<8 | uint32(maskAddr[3])

		networkInt := ipInt & maskInt
		networkAddress := net.IPv4(byte(networkInt>>24), byte(networkInt>>16), byte(networkInt>>8), byte(networkInt)).String()
		broadcastInt := networkInt | (^maskInt & 0xFFFFFFFF)
		broadcastAddress := net.IPv4(byte(broadcastInt>>24), byte(broadcastInt>>16), byte(broadcastInt>>8), byte(broadcastInt)).String()
		wildcardInt := ^maskInt & 0xFFFFFFFF
		wildcard := net.IPv4(byte(wildcardInt>>24), byte(wildcardInt>>16), byte(wildcardInt>>8), byte(wildcardInt)).String()

		availQua := int64(math.Pow(2, float64(32-prefix)))
		if prefix < 30 {
			availQua -= 2
		}
		binaryIP := ""
		binaryNetwork := ""
		for _, octet := range ipAddr {
			binaryIP += fmt.Sprintf("%08b", octet)
		}
		for _, octet := range net.ParseIP(networkAddress).To4() {
			binaryNetwork += fmt.Sprintf("%08b", octet)
		}
		ipNum, _ := strconv.ParseInt(binaryIP, 2, 64)
		netNum, _ := strconv.ParseInt(binaryNetwork, 2, 64)
		availNum := ipNum - netNum

		var availNumStr string
		if prefix < 30 && availNum == 0 {
			availNumStr = "网络地址" + strconv.FormatInt(availNum, 10)
		} else if prefix < 30 && availNum > availQua {
			availNumStr = "广播地址" + strconv.FormatInt(availNum, 10)
		} else if prefix == 31 {
			availNumStr = "特殊可用" + strconv.FormatInt(availNum+1, 10)
		} else if prefix == 32 {
			availNumStr = "主机地址" + strconv.FormatInt(availNum+1, 10)
		} else {
			availNumStr = strconv.FormatInt(availNum, 10)
		}

		class, err := GetNetworkClass(ip)
		if err != nil {
			return fmt.Errorf("failed to get network class: %w", err)
		}

		fmt.Println("---------sub calc (IPv4)---------")
		fmt.Println("IP 位置/可用IP     :", ip, "("+class+")", availNumStr, "/", availQua)
		fmt.Println("网络~广播地址      :", networkAddress, "~", broadcastAddress)
		fmt.Println("掩码|前缀|反掩码   :", subnetMask, "|", prefix, "|", wildcard)

		if subPrefix > 0 && subPrefix > prefix {
			fmt.Println("\n---------DivSubnet---------")
			numSubnets := int(math.Pow(2, float64(subPrefix-prefix)))
			subnetWcInt := ^uint32(0xFFFFFFFF<<(32-subPrefix)) & 0xFFFFFFFF
			subnetWcAddress := net.IPv4(byte(subnetWcInt>>24), byte(subnetWcInt>>16), byte(subnetWcInt>>8), byte(subnetWcInt)).String()
			fmt.Printf("划分 %d 个 (%s | %d | %s) 子网:\n", numSubnets, sub1network, subPrefix, subnetWcAddress)
			for i := 0; i < numSubnets; i++ {
				newNetworkInt := networkInt + uint32(i*int(math.Pow(2, float64(32-subPrefix))))
				newNetworkAddress := net.IPv4(byte(newNetworkInt>>24), byte(newNetworkInt>>16), byte(newNetworkInt>>8), byte(newNetworkInt)).String()
				if (i < 3) || (i > numSubnets-4) {
					if (i == 3) && (4 != numSubnets) {
						i = numSubnets - 4
					}
					newBroadcastInt := newNetworkInt | uint32(math.Pow(2, float64(32-subPrefix))-1)
					newBroadcastAddress := net.IPv4(byte(newBroadcastInt>>24), byte(newBroadcastInt>>16), byte(newBroadcastInt>>8), byte(newBroadcastInt)).String()
					fmt.Printf("子网 %d: %s ~ %s\n", i+1, newNetworkAddress, newBroadcastAddress)
				}

			}
		}
	}
	return nil
}
