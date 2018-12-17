package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

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

type PolicyContainer struct {
	env       string
	region    string
	iam       *iam.IAM
	policyMap map[string]*events.APIGatewayCustomAuthorizerPolicy
}

func New(env, region string) *PolicyContainer {
	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = region

	return &PolicyContainer{env: env, region: region, iam: iam.New(cfg), policyMap: make(map[string]*events.APIGatewayCustomAuthorizerPolicy, 0)}
}

func (p *PolicyContainer) Init(roleArns []string) error {
	log.Info().Strs("roles", roleArns).Msg("parsing roles")
	for _, roleArn := range roleArns {
		roles := strings.Split(roleArn, "/")
		if len(roles) != 2 {
			return errors.New("invalid role, make sure to pass role ARN not role name")
		}
		authorizerPolicy, err := p.GetRolePolicies(roles[1])
		if err != nil {
			return err
		}
		p.policyMap[roleArn] = authorizerPolicy
	}
	return nil
}

// GetRolePolicies takes a roleName and looks up all policies applied to it, converting it to an APIGatewayCustomAuthorizerPolicy
// Note does this take into account ManagedRoles.
func (p *PolicyContainer) GetRolePolicies(roleName string) (*events.APIGatewayCustomAuthorizerPolicy, error) {
	stmts := make([]events.IAMPolicyStatement, 0)

	i := &iam.ListRolePoliciesInput{
		MaxItems: aws.Int64(50),
		RoleName: aws.String(roleName),
	}
	req := p.iam.ListRolePoliciesRequest(i)
	rolePolicies, err := req.Send()
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
		out, err := req.Send()
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

func (p *PolicyContainer) transformPolicy(document string) (string, []events.IAMPolicyStatement, error) {
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
