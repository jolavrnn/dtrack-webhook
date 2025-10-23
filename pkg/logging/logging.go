package logging

import (
	"os"

	"github.com/sirupsen/logrus"
	"go.elastic.co/ecslogrus"
)

func SetupLogging(log *logrus.Logger, levelStr, format string) {
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
	log.SetOutput(os.Stdout)

	if format == "ecs" {
		log.SetFormatter(&ecslogrus.Formatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	log.WithFields(logrus.Fields{
		"level":  level.String(),
		"format": format,
	}).Info("Logger initialized")
}
