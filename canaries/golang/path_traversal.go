package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

// Path traversal vulnerability #1: Direct file access
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Vulnerable: No validation of file path
	// Payload: ../../../etc/passwd
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

// Path traversal vulnerability #2: filepath.Join without validation
func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	baseDir := "/var/uploads/"

	// Vulnerable: filepath.Join doesn't prevent traversal
	// Payload: ../../etc/passwd
	fullPath := filepath.Join(baseDir, filename)

	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	defer file.Close()

	content, _ := ioutil.ReadAll(file)
	w.Write(content)
}

// Path traversal vulnerability #3: Template file inclusion
func renderTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := r.URL.Query().Get("template")

	// Vulnerable: Direct template path construction
	templatePath := "templates/" + templateName + ".html"

	content, err := ioutil.ReadFile(templatePath)
	if err != nil {
		http.Error(w, "Template not found", 404)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

// Path traversal vulnerability #4: Log file access
func viewLogFile(w http.ResponseWriter, r *http.Request) {
	logFile := r.URL.Query().Get("log")
	logDir := "/var/log/app/"

	// Vulnerable: String concatenation allows traversal
	fullPath := logDir + logFile

	content, err := ioutil.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Log file not found", 404)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

// Path traversal vulnerability #5: Config file loading
func loadConfig(configName string) ([]byte, error) {
	// Vulnerable: Direct path construction
	configPath := "/etc/myapp/" + configName

	return ioutil.ReadFile(configPath)
}

func main() {
	http.HandleFunc("/file", serveFile)
	http.HandleFunc("/download", downloadFile)
	http.HandleFunc("/template", renderTemplate)
	http.HandleFunc("/logs", viewLogFile)

	fmt.Println("Starting vulnerable server on :8080")
	http.ListenAndServe(":8080", nil)
}