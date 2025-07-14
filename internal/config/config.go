package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config 主配置结构
type Config struct {
	Processes []string
}

// LoadConfig 从文件加载配置
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开配置文件失败: %w", err)
	}
	defer file.Close()

	var processes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释
		}
		processes = append(processes, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	return &Config{Processes: processes}, nil
}
