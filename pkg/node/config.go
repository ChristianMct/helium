package node

import (
	"encoding/json"
	"os"
)

func LoadConfigFromFile(filename string) (Config, error) {
	// Open the config file
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	// Decode the config file into the config variable
	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
