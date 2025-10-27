package logging

import (
	"os"

	"github.com/sirupsen/logrus"
	"go.elastic.co/ecslogrus"
)

// Use ECS Format to make integration with Elasticsearch easier.
// Or use default, if you won't, I don't judge.
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
