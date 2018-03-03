package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"

	uuid "github.com/satori/go.uuid"
)

const appVersion = "2.0"

var buildTime string
var buildCommit string

var secret = os.Getenv("SECRET")
var command = os.Getenv("R10K_CMD")
var lsock = os.Getenv("LISTEN")
var defaultCommand = "/opt/puppetlabs/puppet/bin/r10k deploy environment -pv info"

// ---

func showInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "r10k-webhook: web-based trigger for r10k"})
}

type gitLabEvent struct {
	ObjectKind   string `json:"object_kind" binding:"required"`
	UserUsername string `json:"user_username" binding:"required"`
	Project      gitLabProject
}

type gitLabProject struct {
	Name       string `json:"name" binding:"required"`
	GitHTTPUrl string `json:"git_http_url" binding:"required"`
}

type gitHubEvent struct {
	Pusher     gitHubPusher     `json:"pusher" binding:"required"`
	Repository gitHubRepository `json:"repository" binding:"required"`
}

type gitHubPusher struct {
	Name string `json:"name" binding:"required"`
}

type gitHubRepository struct {
	Name    string `json:"name" binding:"required"`
	HTMLUrl string `json:"html_url" binding:"required"`
}

func validateGitLabRequest(rid string, c *gin.Context) error {

	// connection from GitLab
	log.Printf("[%s] X-Gitlab-Event: %s", rid, c.GetHeader("X-Gitlab-Event"))
	log.Printf("[%s] X-Gitlab-Token: %s", rid, c.GetHeader("X-Gitlab-Token"))

	if c.GetHeader("X-Gitlab-Event") != "Push Hook" {
		log.Printf("[%s] E: Invalid event", rid)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Invalid event"})
		return fmt.Errorf("Invalid event")
	}
	if c.GetHeader("X-Gitlab-Token") != secret {
		log.Printf("[%s] E: Invalid token", rid)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "Invalid token"})
		return fmt.Errorf("Invalid token")
	}

	/*
		body, _ := c.GetRawData()
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		log.Printf("Payload:\n%s", body)
	*/

	var json gitLabEvent
	if err := c.ShouldBindJSON(&json); err != nil {
		log.Printf("[%s] E: Failed to parse request body", rid)
		c.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{
				"status":  http.StatusBadRequest,
				"message": "Failed to parse request body",
				"error":   err.Error(),
			})
		return err
	}

	log.Printf("[%s] User %s pushed update to %s (%s)",
		rid, json.UserUsername, json.Project.Name, json.Project.GitHTTPUrl)

	return nil
}

func validateGitHubRequest(rid string, c *gin.Context) error {

	// connection from GitHub
	log.Printf("[%s] X-GitHub-Event : %s", rid, c.GetHeader("X-GitHub-Event"))
	log.Printf("[%s] X-Hub-Signature: %s", rid, c.GetHeader("X-Hub-Signature"))

	if c.GetHeader("X-GitHub-Event") != "push" && c.GetHeader("X-GitHub-Event") != "ping" {
		log.Printf("[%s] E: Invalid event", rid)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Invalid event"})
		return fmt.Errorf("Invalid event")
	}

	body, _ := c.GetRawData()
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	//log.Printf("Payload:\n%s", body)

	mac := hmac.New(sha1.New, []byte("secret"))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	if hmac.Equal(expectedMAC, []byte(strings.TrimPrefix(c.GetHeader("X-Hub-Signature"), "sha1="))) {
		log.Printf("[%s] E: Invalid signature", rid)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "Invalid signature"})
		return fmt.Errorf("Invalid signature")
	}

	if c.GetHeader("X-GitHub-Event") == "ping" {
		log.Printf("[%s] Received ping event", rid)
		c.JSON(http.StatusOK, gin.H{
			"status":  http.StatusOK,
			"message": "pong",
		})
		return fmt.Errorf("Ping request, not proceeding")
	}

	var json gitHubEvent
	if err := c.ShouldBindJSON(&json); err != nil {
		log.Printf("[%s] E: Failed to parse request body", rid)
		c.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{
				"status":  http.StatusBadRequest,
				"message": "Failed to parse request body",
				"error":   err.Error(),
			})
		return err
	}

	log.Printf("[%s] User %s pushed update to %s (%s)",
		rid, json.Pusher.Name, json.Repository.Name, json.Repository.HTMLUrl)

	return nil
}

func refreshRepo(c *gin.Context) {
	rid := uuid.Must(uuid.NewV4()).String()[:8]

	var e error
	if c.GetHeader("X-Gitlab-Event") != "" {
		e = validateGitLabRequest(rid, c)
	} else if c.GetHeader("X-GitHub-Event") != "" {
		e = validateGitHubRequest(rid, c)
	} else {
		e = fmt.Errorf("Invalid request")
		log.Printf("[%s] E: Invalid request", rid)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "message": "Invalid request, missing required headers"})
	}
	if e != nil {
		return
	}

	cmd := exec.Command("/usr/bin/env",
		strings.Fields(command)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[%s] E: r10k execution failed", rid)
		log.Printf("[%s] E:    error: %v", rid, err)
		log.Printf("[%s] E:   output: %v", rid, string(output))

		c.AbortWithStatusJSON(http.StatusInternalServerError,
			gin.H{
				"status":  http.StatusInternalServerError,
				"message": "r10k execution failed",
				"error":   err.Error(),
				"output":  string(output),
			})
		return
	}

	log.Printf("[%s] r10k completed, output:\n---\n%s---", rid, string(output))

	c.JSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
		"data": gin.H{
			"r10k_output": strings.Split(string(output), "\n"),
		},
	})

	log.Printf("[%s] Completed", rid)
}

func main() {

	if command == "" {
		command = defaultCommand
	}
	if lsock == "" {
		lsock = ":8000"
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("Starting r10k-webhook v%s on %s", appVersion, lsock)
	log.Printf("Build time  : %s", buildTime)
	log.Printf("Commit hash : %s", buildCommit)
	log.Printf("Secret is set to: %s", secret)

	r := gin.Default()

	v1 := r.Group("/api/v1")

	v1.GET("/", showInfo)
	v1.POST("/refresh", refreshRepo)

	log.Fatal(r.Run(lsock))
}
