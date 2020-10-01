package main

import (
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Formatter type for logrus
type Formatter struct {
	TimestampFormat string
	LogFormat       string
}

// Format builds the log message.
// Inspiration from: https://github.com/t-tomalak/logrus-easy-formatter
func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	output := time.Now().Format(time.RFC3339) + " " + strings.ToUpper(entry.Level.String()) +
		" - 0 " + os.Getenv("SERVICE_NAME") + " " + "admission-controller" +
		" {\"@message\":\"" + entry.Message + "\"}\n"

	return []byte(output), nil
}
