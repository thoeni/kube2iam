package iam

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/karlseguin/ccache"
)

var cache = ccache.New(ccache.Configure())

const (
	maxSessNameLength = 64
	ttl               = time.Minute * 15
)

// Client represents an IAM client.
type Client struct {
	BaseARN string
}

// Credentials represent the security Credentials response.
type Credentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	Code            string
	Expiration      string
	LastUpdated     string
	SecretAccessKey string
	Token           string
	Type            string
}

func getHash(text string) string {
	h := fnv.New32a()
	_, err := h.Write([]byte(text))
	if err != nil {
		return text
	}
	return fmt.Sprintf("%x", h.Sum32())
}

// GetInstanceIAMRole get instance IAM role from metadata service.
func GetInstanceIAMRole() (string, error) {
	sess, err := session.NewSession()
	if err != nil {
		return "", err
	}
	metadata := ec2metadata.New(sess)
	if !metadata.Available() {
		return "", errors.New("EC2 Metadata is not available, are you running on EC2?")
	}
	iamRole, err := metadata.GetMetadata("iam/security-credentials/")
	if err != nil {
		return "", err
	}
	if iamRole == "" || err != nil {
		return "", errors.New("EC2 Metadata didn't returned any IAM Role")
	}
	return iamRole, nil
}

func sessionName(roleARN, remoteIP string) string {
	idx := strings.LastIndex(roleARN, "/")
	name := fmt.Sprintf("%s-%s", getHash(remoteIP), roleARN[idx+1:])
	return fmt.Sprintf("%.[2]*[1]s", name, maxSessNameLength)
}

type Prefetcher struct {
	RoleARNTickers map[string]*RoleARNTicker
	RoleARNs       chan RoleARN
}

type RoleARN struct {
	arn      string
	remoteIP string
}

type RoleARNTicker struct {
	roleArn RoleARN
	ticker  *time.Ticker
	iam     *Client
}

func (p *Prefetcher) Start(iam *Client) {
	go func() {
		for newARNRole := range p.RoleARNs {
			log.Printf("Received request for ARNRole: %s - RemoteIP: %s", newARNRole.arn, newARNRole.remoteIP)
			if _, exists := p.RoleARNTickers[newARNRole.arn]; !exists {
				log.Printf("Creating new ticker for ARNRole: %s", newARNRole.arn)
				ticker := time.NewTicker(ttl - 1*time.Minute)
				(*p).RoleARNTickers[newARNRole.arn] = &RoleARNTicker{RoleARN{newARNRole.arn, newARNRole.remoteIP}, ticker, iam}

				go ((*p).RoleARNTickers[newARNRole.arn]).prefetch()
			} else {
				log.Printf("Ticker already exists for ARNRole: %s. Updating remoteIP: [%s] => [%s]", newARNRole.arn, (*(*p).RoleARNTickers[newARNRole.arn]).roleArn.remoteIP, newARNRole.remoteIP)
				(*(*p).RoleARNTickers[newARNRole.arn]).roleArn.remoteIP = newARNRole.remoteIP
			}
		}
	}()
}

func (p *Prefetcher) Stop() {
	log.Printf("Called Prefetcher Stop")
	close(p.RoleARNs)
	log.Printf("Closed Prefetcher channel")
	for _, t := range p.RoleARNTickers {
		log.Printf("Stopping ticker for ARNRole: %s", t.roleArn.arn)
		t.ticker.Stop()
	}
	p.RoleARNTickers = make(map[string]*RoleARNTicker)
	p.RoleARNs = make(chan RoleARN)
	log.Printf("Prefercher stopped")
}

func (t RoleARNTicker) prefetch() {
	log.Printf("Starting prefetch routine for ARNRole: %s", t.roleArn.arn)
	for range t.ticker.C {
		log.Printf("Assuming role for ARNRole: %s, remoteIP: %s", t.roleArn.arn, t.roleArn.remoteIP)
		t.iam.AssumeRole(t.roleArn.arn, t.roleArn.remoteIP)
	}
}

var Pref *Prefetcher

// AssumeRole returns an IAM role Credentials using AWS STS.
func (iam *Client) AssumeRole(roleARN, remoteIP string) (*Credentials, error) {
	if Pref != nil {
		log.Printf("AssumeRole endpoint called for ARNRole: %s. Sending notification to Prefetcher.", roleARN)
		(*Pref).RoleARNs <- RoleARN{
			arn:      roleARN,
			remoteIP: remoteIP,
		}
	}
	item, err := cache.Fetch(roleARN, ttl, func() (interface{}, error) {
		sess, err := session.NewSession()
		if err != nil {
			return nil, err
		}
		svc := sts.New(sess, &aws.Config{LogLevel: aws.LogLevel(2)})
		resp, err := svc.AssumeRole(&sts.AssumeRoleInput{
			DurationSeconds: aws.Int64(int64(ttl.Seconds() * 2)),
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(sessionName(roleARN, remoteIP)),
		})
		if err != nil {
			return nil, err
		}

		return &Credentials{
			AccessKeyID:     *resp.Credentials.AccessKeyId,
			Code:            "Success",
			Expiration:      resp.Credentials.Expiration.Format("2006-01-02T15:04:05Z"),
			LastUpdated:     time.Now().Format("2006-01-02T15:04:05Z"),
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			Token:           *resp.Credentials.SessionToken,
			Type:            "AWS-HMAC",
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return item.Value().(*Credentials), nil
}

// NewClient returns a new IAM client.
func NewClient(baseARN string) *Client {
	return &Client{BaseARN: baseARN}
}
