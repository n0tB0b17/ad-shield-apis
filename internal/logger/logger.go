package logger

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	Debug LogLevel = iota //0
	Info                  //1
	Warn                  //2
	Error                 //3
	Fatal                 //4
)

type Logger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string)
	Fatal(msg string)
}

type FileLogger struct {
	lvl  LogLevel
	file *os.File
}

func NewFileLogger(lvl LogLevel, filePath string) (*FileLogger, error) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("Error while opening file: %w \n", err)
	}

	return &FileLogger{
		lvl:  lvl,
		file: f,
	}, nil
}

func (fl *FileLogger) log(lvl LogLevel, msg string) {
	if lvl < fl.lvl {
		return
	}

	log.SetOutput(fl.file)
	log.Printf("[%s]>> | %s", levelToString(lvl), msg)
}

func (fl *FileLogger) Debug(msg string) { fl.log(Debug, msg) }
func (fl *FileLogger) Info(msg string)  { fl.log(Info, msg) }
func (fl *FileLogger) Warn(msg string)  { fl.log(Warn, msg) }
func (fl *FileLogger) Error(msg string) { fl.log(Error, msg) }
func (fl *FileLogger) Fatal(msg string) {
	fl.log(Fatal, msg)
	os.Exit(1)
}

func levelToString(lvl LogLevel) string {
	switch lvl {
	case Debug:
		return "Debug"
	case Info:
		return "Info"
	case Warn:
		return "Warn"
	case Error:
		return "Error"
	case Fatal:
		return "Fatal"
	default:
		return "UNKNOWN"
	}
}
