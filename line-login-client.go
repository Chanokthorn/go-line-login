package go_line_login

import (
	"context"
	"encoding/json"
	"fmt"

	"gopkg.in/resty.v1"
)

type VerifyResponse struct {
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	ExpiresIn int    `json:"expires_in"`
}

type GetProfileResponse struct {
	UserId        string `json:"userId"`
	DisplayName   string `json:"displayName"`
	PictureUrl    string `json:"pictureUrl"`
	StatusMessage string `json:"statusMessage"`
}

type Profile struct {
	GetProfileResponse
}

type LineLogin interface {
	Verify(ctx context.Context, accessToken string) (clientID string, err error)
	GetProfile(ctx context.Context, accessToken string) (profile Profile, err error)
}

type lineLogin struct {
	oauthClient *resty.Client
	client      *resty.Client
}

func NewLineLogin(oauthEndpoint string, endpoint string) LineLogin {
	return &lineLogin{
		oauthClient: resty.New().SetHostURL(oauthEndpoint),
		client:      resty.New().SetHostURL(endpoint),
	}
}

func (l lineLogin) Verify(ctx context.Context, accessToken string) (string, error) {
	res, err := l.oauthClient.R().SetContext(ctx).
		SetQueryParam("access_token", accessToken).
		Get("/v2.1/verify")
	if err != nil || res.StatusCode() != 200 {
		return "", fmt.Errorf("failed to verify access token: %v", err)
	}

	var verifyResponse VerifyResponse
	if err := json.Unmarshal(res.Body(), &verifyResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal verify response: %v", err)
	}

	return verifyResponse.ClientID, nil
}

func (l lineLogin) GetProfile(ctx context.Context, accessToken string) (profile Profile, err error) {
	res, err := l.client.R().SetContext(ctx).
		SetAuthToken(accessToken).
		Get("/v2/profile")
	if err != nil || res.StatusCode() != 200 {
		return Profile{}, fmt.Errorf("failed to get profile: %v", err)
	}

	if err := json.Unmarshal(res.Body(), &profile); err != nil {
		return Profile{}, fmt.Errorf("failed to unmarshal profile: %v", err)
	}

	return profile, nil
}
