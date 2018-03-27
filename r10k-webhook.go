package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	uuid "github.com/satori/go.uuid"
)

const appVersion = "2.1"

var buildTime string
var buildCommit string

var config struct {
	secret  string // Env SECRET
	command string // Env R10K_CMD
	timeout int    // Env R10K_TMOUT
	lsock   string // Env LISTEN
}

var runmu sync.Mutex
var cntmu sync.RWMutex
var cnt = 0
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
	if c.GetHeader("X-Gitlab-Token") != config.secret {
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

	cntmu.RLock()
	if cnt > 1 {
		// we already have a waiting goroutine for deploy, no need to stack more
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"data": gin.H{
				"message": "no changes necessary, deployment in progress\b",
			},
		})
		log.Printf("[%s] No changes necessary, deployment in progress", rid)
		cntmu.RUnlock()
		return
	}
	log.Printf("[%s] Checking r10k is not running ...", rid)
	cntmu.RUnlock()

	cntmu.Lock()
	cnt++
	cntmu.Unlock()

	runmu.Lock()
	defer func() { cntmu.Lock(); cnt--; cntmu.Unlock() }()
	defer runmu.Unlock()
	log.Printf("[%s] Spawning r10k ...", rid)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, strings.Fields(config.command)[0],
		strings.Fields(config.command)[1:]...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded || err != nil {
		log.Printf("[%s] E: r10k execution failed", rid)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[%s] E: r10k took too long to finish and was killed.", rid)

		} else {
			log.Printf("[%s] E:    error: %v", rid, err)
		}
		log.Printf("[%s] E:   output: %v", rid, string(output))

		// kill stray r10k processes
		user, _ := user.Current()
		ps := exec.Command("/bin/ps", "-fu", user.Username)
		psout, _ := ps.CombinedOutput()
		lines := strings.Split(string(psout), "\n")
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) > 8 && f[2] == "1" && f[8] == "/opt/puppetlabs/puppet/bin/r10k" {
				log.Printf("[%s] E: found stray r10k:", rid)
				log.Printf("[%s]    %s", rid, l)
				pid, err2 := strconv.Atoi(f[1])
				if err2 == nil {
					syscall.Kill(pid, syscall.SIGKILL)
					log.Printf("[%s]    Killed PID = %d", rid, pid)
				}
			}
		}

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

func init() {
	var err error

	config.secret = os.Getenv("SECRET")
	config.lsock = os.Getenv("LISTEN")
	config.command = os.Getenv("R10K_CMD")
	config.timeout, err = strconv.Atoi(os.Getenv("R10K_TMOUT"))
	if err != nil {
		config.timeout = 60
	}

	if config.command == "" {
		config.command = defaultCommand
	}
	if config.lsock == "" {
		config.lsock = ":8000"
	}

}

func main() {

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("Starting r10k-webhook v%s on %s", appVersion, config.lsock)
	log.Printf("Build time  : %s", buildTime)
	log.Printf("Commit hash : %s", buildCommit)
	log.Printf("Secret is set to: %s", config.secret)

	r := gin.Default()

	v1 := r.Group("/api/v1")

	v1.GET("/", showInfo)
	v1.POST("/refresh", refreshRepo)

	log.Fatal(r.Run(config.lsock))
}
