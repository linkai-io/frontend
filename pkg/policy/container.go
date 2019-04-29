package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/rs/zerolog/log"
)

type PolicyDocument struct {
	Version   string                 `json:"Version"`
	Statement []PolicyArrayStatement `json:"Statement,omitempty"`
}

type PolicyArrayDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement,omitempty"`
}

type PolicyArrayStatement struct {
	Action   []string `json:"Action"`
	Effect   string   `json:"Effect"`
	Resource []string `json:"Resource"`
}

type PolicyStatement struct {
	Action   string   `json:"Action"`
	Effect   string   `json:"Effect"`
	Resource []string `json:"Resource"`
}

type Container struct {
	env       string
	region    string
	iam       *iam.IAM
	policyMap map[string]*events.APIGatewayCustomAuthorizerPolicy // rolename (owner/admin) : policy
}

func New(env, region string) *Container {
	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = region

	return &Container{env: env, region: region, iam: iam.New(cfg), policyMap: make(map[string]*events.APIGatewayCustomAuthorizerPolicy, 0)}
}

func (p *Container) Init(roles map[string]string) error {
	log.Info().Msg("parsing roles")

	for roleName, roleArn := range roles {
		log.Info().Str("name", roleName).Str("arn", roleArn).Msg("parsing policy")
		roleParts := strings.Split(roleArn, "/")
		if len(roleParts) != 2 {
			return errors.New("invalid role, make sure to pass role ARN not role name")
		}

		authorizerPolicy, err := p.GetRolePolicies(roleParts[1])
		if err != nil {
			return err
		}
		p.policyMap[roleName] = authorizerPolicy
	}
	return nil
}

// GetPolicy returns the policy that was cached from Init
func (p *Container) GetPolicy(roleName string) (*events.APIGatewayCustomAuthorizerPolicy, error) {
	var policy *events.APIGatewayCustomAuthorizerPolicy
	var ok bool

	if policy, ok = p.policyMap[roleName]; !ok {
		return nil, errors.New("unknown role")
	}
	return policy, nil
}

// GetRolePolicies takes a roleName and looks up all policies applied to it, converting it to an APIGatewayCustomAuthorizerPolicy
// Note does this take into account ManagedRoles.
func (p *Container) GetRolePolicies(roleName string) (*events.APIGatewayCustomAuthorizerPolicy, error) {
	stmts := make([]events.IAMPolicyStatement, 0)

	i := &iam.ListRolePoliciesInput{
		MaxItems: aws.Int64(50),
		RoleName: aws.String(roleName),
	}
	req := p.iam.ListRolePoliciesRequest(i)
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	rolePolicies, err := req.Send(timeoutCtx)
	if err != nil {
		return nil, err
	}

	for _, policyName := range rolePolicies.PolicyNames {
		var policyStatements []events.IAMPolicyStatement

		input := &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		}
		req := p.iam.GetRolePolicyRequest(input)
		out, err := req.Send(timeoutCtx)
		if err != nil {
			return nil, err
		}

		_, policyStatements, err = p.transformPolicy(*out.PolicyDocument)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, policyStatements...)
	}

	return &events.APIGatewayCustomAuthorizerPolicy{
		Version:   "2012-10-17",
		Statement: stmts,
	}, nil
}

func (p *Container) transformPolicy(document string) (string, []events.IAMPolicyStatement, error) {
	doc, _ := url.PathUnescape(document)
	policy := &PolicyDocument{}
	arrPolicy := &PolicyArrayDocument{}

	if err := json.Unmarshal([]byte(doc), policy); err == nil {
		stmts := make([]events.IAMPolicyStatement, len(policy.Statement))
		for i, stmt := range policy.Statement {
			stmts[i] = events.IAMPolicyStatement{
				Action:   stmt.Action,
				Effect:   stmt.Effect,
				Resource: stmt.Resource,
			}
		}

		return "", stmts, nil
	}

	err := json.Unmarshal([]byte(doc), arrPolicy)
	if err != nil {
		return "", nil, err
	}

	stmts := make([]events.IAMPolicyStatement, len(arrPolicy.Statement))
	for i, stmt := range arrPolicy.Statement {
		stmts[i] = events.IAMPolicyStatement{
			Action:   []string{stmt.Action},
			Effect:   stmt.Effect,
			Resource: stmt.Resource,
		}
	}

	return "", stmts, nil
}
