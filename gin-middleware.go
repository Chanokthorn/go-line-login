package go_line_login

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	profileKey = "profile"
)

func NewLineLoginMiddleware(channelID string, login LineLogin) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, valid := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !valid || accessToken == "" {
			c.JSON(401, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}

		clientID, err := login.Verify(c, accessToken)
		if err != nil {
			c.JSON(401, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}

		if clientID != channelID {
			c.JSON(401, gin.H{"error": "invalid access token"})
			c.Abort()
			return
		}

		profile, err := login.GetProfile(c, accessToken)
		if err != nil {
			c.JSON(401, gin.H{"error": "unable to get profile"})
			c.Abort()
			return
		}

		c.Set(profileKey, profile)

		c.Next()
	}
}

func GetProfile(c *gin.Context) (Profile, error) {
	profile, exists := c.Get(profileKey)
	if !exists {
		return Profile{}, errors.New("profile not found")
	}

	return profile.(Profile), nil
}
