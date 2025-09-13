package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/virtualzone/onedrive-uploader/sdk"
)

type CommandFunction func(client *sdk.Client, renderer *OutputRenderer, args []string)

type CommandFunctionDefinition struct {
	Fn              CommandFunction
	MinArgs         int
	InitSecretStore bool
	RequireConfig   bool
}

var (
	commands = map[string]*CommandFunctionDefinition{
		"config":   {Fn: cmdConfig, MinArgs: 0, InitSecretStore: false, RequireConfig: false},
		"login":    {Fn: cmdLogin, MinArgs: 0, InitSecretStore: false, RequireConfig: true},
		"mkdir":    {Fn: cmdCreateDir, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"upload":   {Fn: cmdUpload, MinArgs: 2, InitSecretStore: true, RequireConfig: true},
		"download": {Fn: cmdDownload, MinArgs: 2, InitSecretStore: true, RequireConfig: true},
		"rm":       {Fn: cmdDelete, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"ls":       {Fn: cmdList, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"info":     {Fn: cmdInfo, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"sha1":     {Fn: cmdSHA1, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"sha256":   {Fn: cmdSHA256, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"cd":       {Fn: cmdCD, MinArgs: 1, InitSecretStore: true, RequireConfig: true},
		"pwd":      {Fn: cmdPwd, MinArgs: 0, InitSecretStore: false, RequireConfig: true},
		"migrate":  {Fn: cmdMigrateConfig, MinArgs: 1, InitSecretStore: false, RequireConfig: false},
		"version":  {Fn: cmdVersion, MinArgs: 0, InitSecretStore: false, RequireConfig: false},
	}
)

func cmdConfig(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath, err := findConfigFilePath()
	if err != nil {
		logError("Could not init config path: " + err.Error())
		return
	}
	interactiveConfig := &InteractiveConfig{
		TargetPath: targetPath,
	}
	interactiveConfig.Run()
}

func cmdMigrateConfig(client *sdk.Client, renderer *OutputRenderer, args []string) {
	type secretStore struct {
		AccessToken  string    `json:"access_token"`
		RefreshToken string    `json:"refresh_token"`
		Expiry       time.Time `json:"expiry"`
	}

	readSecretJson := func(filename string) (*secretStore, error) {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		var config secretStore
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
		return &config, nil
	}

	sourceConfig, err := sdk.ReadConfig(args[0])
	if err != nil {
		logError("Could not read source config: " + err.Error())
		return
	}
	sourceSecret, err := readSecretJson(sourceConfig.SecretStore)
	if err != nil {
		logError("Could not read source secret: " + err.Error())
		return
	}
	targetPath, err := findConfigFilePath()
	if err != nil {
		logError("Could not init target config: " + err.Error())
		return
	}
	targetConfig := &sdk.Config{
		ConfigFilePath: targetPath,
		ClientID:       sourceConfig.ClientID,
		ClientSecret:   sourceConfig.ClientSecret,
		Scopes:         sourceConfig.Scopes,
		RedirectURL:    sourceConfig.RedirectURL,
		Root:           sourceConfig.Root,
		AccessToken:    sourceSecret.AccessToken,
		RefreshToken:   sourceSecret.RefreshToken,
		Expiry:         sourceSecret.Expiry,
	}
	if err := targetConfig.Write(); err != nil {
		logError("Could not write target config: " + err.Error())
		return
	}
	log("Configuration migrated.")
}

func cmdLogin(client *sdk.Client, renderer *OutputRenderer, args []string) {
	log("------------------------------------")
	log("Open a browser and go to:")
	print(client.GetLoginURL())
	log("------------------------------------")
	renderer.initSpinner("Waiting for code...")
	err := client.Login()
	renderer.stopSpinner()
	if err != nil {
		logError("Could not log in: " + err.Error())
		return
	}
	log("Login successful.")
}

func cmdCreateDir(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Creating directory...")
	err := client.CreateDir(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not create folder: " + err.Error())
		return
	}
	log("Folder created.")
}

func cmdUpload(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetFolder := resolvePath(args[len(args)-1], client.Config.CurrentDirectory)
	sourceFiles := args[:len(args)-1]
	numFiles := 0
	for _, sourceFile := range sourceFiles {
		fileStat, err := os.Stat(sourceFile)
		if err != nil {
			logError("Could not get stats for local file: " + err.Error())
			return
		}
		// Skip directories
		if fileStat.IsDir() {
			continue
		}
		// Upload file
		numFiles++
		client.ResetChannels()
		done := false
		go func() {
			fileStat := <-client.ChannelTransferStart
			renderer.initProgressBar(fileStat.Size(), "Uploading "+fmt.Sprintf("%-20s", cutString(fileStat.Name(), 17)+"..."))
		}()
		go func() {
			for !done {
				bytes := <-client.ChannelTransferProgress
				renderer.updateProgressBar(bytes)
			}
		}()
		go func() {
			done = <-client.ChannelTransferFinish
		}()
		err = client.Upload(sourceFile, targetFolder)
		if err != nil {
			logError("Could not upload file: " + err.Error())
			return
		}
	}
	if numFiles == 0 {
		logError("No files for uploading specified (uploading directories is not supported)")
	}
}

func cmdDownload(client *sdk.Client, renderer *OutputRenderer, args []string) {
	sourcePath := resolvePath(args[0], client.Config.CurrentDirectory)
	done := false
	go func() {
		var fileStat fs.FileInfo = nil
		for fileStat == nil {
			fileStat := <-client.ChannelTransferStart
			if fileStat == nil {
				renderer.initSpinner("Retrieving information...")
			} else {
				renderer.stopSpinner()
				renderer.initProgressBar(fileStat.Size(), "Downloading "+fileStat.Name()+"...")
			}
		}
	}()
	go func() {
		for !done {
			bytes := <-client.ChannelTransferProgress
			renderer.updateProgressBar(bytes)
		}
	}()
	go func() {
		done = <-client.ChannelTransferFinish
	}()
	err := client.Download(sourcePath, args[1])
	if err != nil {
		logError("Could not download file: " + err.Error())
		return
	}
	log("File downloaded.")
}

func cmdDelete(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Deleting...")
	err := client.Delete(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not delete: " + err.Error())
		return
	}
	log("Deleted.")
}

func cmdList(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Retrieving directory listing...")
	list, err := client.List(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not list: " + err.Error())
		return
	}
	for _, item := range list {
		itemType := "d"
		if item.File.MimeType != "" {
			itemType = "f"
		}
		print(itemType + " " + item.Name)
	}
}

func cmdInfo(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Retrieving information...")
	item, err := client.Info(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not get info: " + err.Error())
		return
	}
	itemType := "folder"
	if item.Type == sdk.DriveItemTypeFile {
		itemType = "file"
	}
	print("Type:           " + itemType)
	print("Size:           " + strconv.FormatInt(item.SizeBytes, 10) + " bytes")
	if itemType == "folder" {
		print("Child Count:    " + strconv.Itoa(item.Folder.ChildCount))
	} else {
		print("MIME Type:      " + item.File.MimeType)
		print("SHA1 Hash:      " + item.File.Hashes.SHA1)
		print("SHA256 Hash:    " + item.File.Hashes.SHA256)
		print("Quick XOR Hash: " + item.File.Hashes.QuickXOR)
	}
}

func cmdSHA1(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Retrieving SHA1 hash...")
	item, err := client.Info(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not get info: " + err.Error())
		return
	}
	print(item.File.Hashes.SHA1)
}

func cmdSHA256(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)
	renderer.initSpinner("Retrieving SHA256 hash...")
	item, err := client.Info(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not get info: " + err.Error())
		return
	}
	print(item.File.Hashes.SHA256)
}

func cmdCD(client *sdk.Client, renderer *OutputRenderer, args []string) {
	targetPath := resolvePath(args[0], client.Config.CurrentDirectory)

	// Check if the path exists and is a folder
	renderer.initSpinner("Checking directory...")
	item, err := client.Info(targetPath)
	renderer.stopSpinner()
	if err != nil {
		logError("Could not access directory: " + err.Error())
		return
	}

	// Check if it's a folder
	if item.Type != sdk.DriveItemTypeFolder {
		logError("Path is not a directory")
		return
	}

	// Update current directory in config and save
	client.Config.CurrentDirectory = targetPath
	if err := client.Config.Write(); err != nil {
		logError("Could not save configuration: " + err.Error())
		return
	}

	log("Changed directory to: " + targetPath)
}

func cmdPwd(client *sdk.Client, renderer *OutputRenderer, args []string) {
	print(client.Config.CurrentDirectory)
}

func cmdVersion(client *sdk.Client, renderer *OutputRenderer, args []string) {
	print(AppVersion)
}

func cutString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// resolvePath converts relative paths (starting with .) to absolute paths using current directory from config
func resolvePath(path string, currentDir string) string {
	if strings.HasPrefix(path, ".") {
		// Replace . with current directory
		if currentDir == "/" {
			// If current directory is /, just remove the .
			return strings.TrimPrefix(path, ".")
		} else {
			// Replace . with current directory
			return currentDir + strings.TrimPrefix(path, ".")
		}
	}
	return path
}
