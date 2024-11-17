package main

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/trumbooosahil/jwks/pkg/jwks"
)

func BenchmarkDecodeWithGetPublicKeyFromToken(b *testing.B) {
	client, err := jwks.NewClient("https://deriv.okta.com", jwks.CacheConfig{
		CacheEnabled:    true,
		CacheMaxEntries: 5,
		CacheMaxAge:     time.Hour,
	})
	if err != nil {
		b.Fatalf("Failed to create JWKS client: %v", err)
	}

	tokenString := "eyJraWQiOiJManJQUk5mVnhZdWRNcTNtSWl1Mi12ck5VU0xPTXBhbi1aZDhLVmhyMEV3IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHU1YXhiYm4xdVgzUW1IcTY5NyIsIm5hbWUiOiJNb2hkIFNoYWZpIFRydW1ib28iLCJlbWFpbCI6Im1vaGQuc2hhZmlAcmVnZW50bWFya2V0cy5jb20iLCJ2ZXIiOjEsImlzcyI6Imh0dHBzOi8vZGVyaXYub2t0YS5jb20iLCJhdWQiOiIwb2FsMncyMWYyWFVxbXFzSTY5NyIsImlhdCI6MTczMTY3NjIzNCwiZXhwIjoxNzMxNjc5ODM0LCJqdGkiOiJJRC5IOFUwcUFRUXo1Q2J1TnhzcjJnTUpBU2o3T1hEZDRWczJEWnA1ZVNQZXNFIiwiYW1yIjpbInN3ayIsIm1mYSIsInB3ZCJdLCJpZHAiOiIwMG8xNmRieTVtcUxJZHdOMzY5NyIsIm5vbmNlIjoicmFuZG9tTm9uY2U3NyIsInByZWZlcnJlZF91c2VybmFtZSI6Im1vaGQuc2hhZmlAcmVnZW50bWFya2V0cy5jb20iLCJhdXRoX3RpbWUiOjE3MzE1NjI2MDMsImF0X2hhc2giOiJJcGo1S3BCb1lZaldLZU1JSFlCVWh3IiwiZ3JvdXBzIjpbIkNsaWNrVXAiLCJFdmVyeW9uZSIsIkdpdGh1YiAtIGRlcml2LWVudGVycHJpc2Ugb3JnIiwiU0NXX0ludGVybmFsIElUIGFuZCAzcmQgUGFydGllcyIsIlNhZ2UgUGVvcGxlIiwiZ3JhZmFuYV9zZWN1cml0eV9yZWFkb25seSIsIkRhdGFkb2cgUHJvZHVjdGlvbiIsIkdvb2dsZSBXb3Jrc3BhY2UiLCJHaXRodWIgLSByZWdlbnRtYXJrZXRzIG9yZyIsIkdlbmVyYWwiLCJEYXRhZG9nIFFBIiwiTGFzdFBhc3MiLCJHaXRodWIgLSBiaW5hcnktY29tIG9yZyIsIkJhY2tPZmZpY2UgQ2VsbCJdfQ.Twu-ZbvTxscbUdFooYi6hu3jZCjyBm8zwqIrIwm271JF_g2N2iPFeypnhmNdQisXOQpj4t7D8MFDcQY-IaWF5azObgyBqwBu4Chm7vc3heRMboOeTIXtkaQkRmVCle8TP8y2pyvBgKzSwDF3xRKASIApTrOLQ7EsIXFtPImmtB7Y23Y2NvZfWTj6rKcwly5y_umI3rPzDYwj8E6QUAm2QTQ0DXFqsrrRaKHnUA74Z534J4HY0HHHtVnDRyMRRFMU4_ZoMoUL1yNc2iz0im-qsaecwbBDR7L9jeKKJKjuAE6IKdkTFxeqy295nyLT3PJM4B4IBGDhG5XgnJUGHIAy-Q"

	for i := 0; i < b.N; i++ {
		publicKey, err := client.GetPublicKeyFromToken(tokenString)
		if err != nil {
			b.Fatalf("Error retrieving public key: %v", err)
		}

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			//	b.Fatalf("Error decoding token: %v", err)
		}

		if !token.Valid {
			//	b.Fatalf("Invalid token")
		}
	}
}

func BenchmarkDecodeWithGetKeyFunc(b *testing.B) {
	client, err := jwks.NewClient("https://deriv.okta.com", jwks.CacheConfig{
		CacheEnabled:    true,
		CacheMaxEntries: 5,
		CacheMaxAge:     time.Hour,
	})
	if err != nil {
		b.Fatalf("Failed to create JWKS client: %v", err)
	}

	tokenString := "eyJraWQiOiJManJQUk5mVnhZdWRNcTNtSWl1Mi12ck5VU0xPTXBhbi1aZDhLVmhyMEV3IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHU1YXhiYm4xdVgzUW1IcTY5NyIsIm5hbWUiOiJNb2hkIFNoYWZpIFRydW1ib28iLCJlbWFpbCI6Im1vaGQuc2hhZmlAcmVnZW50bWFya2V0cy5jb20iLCJ2ZXIiOjEsImlzcyI6Imh0dHBzOi8vZGVyaXYub2t0YS5jb20iLCJhdWQiOiIwb2FsMncyMWYyWFVxbXFzSTY5NyIsImlhdCI6MTczMTY3NjIzNCwiZXhwIjoxNzMxNjc5ODM0LCJqdGkiOiJJRC5IOFUwcUFRUXo1Q2J1TnhzcjJnTUpBU2o3T1hEZDRWczJEWnA1ZVNQZXNFIiwiYW1yIjpbInN3ayIsIm1mYSIsInB3ZCJdLCJpZHAiOiIwMG8xNmRieTVtcUxJZHdOMzY5NyIsIm5vbmNlIjoicmFuZG9tTm9uY2U3NyIsInByZWZlcnJlZF91c2VybmFtZSI6Im1vaGQuc2hhZmlAcmVnZW50bWFya2V0cy5jb20iLCJhdXRoX3RpbWUiOjE3MzE1NjI2MDMsImF0X2hhc2giOiJJcGo1S3BCb1lZaldLZU1JSFlCVWh3IiwiZ3JvdXBzIjpbIkNsaWNrVXAiLCJFdmVyeW9uZSIsIkdpdGh1YiAtIGRlcml2LWVudGVycHJpc2Ugb3JnIiwiU0NXX0ludGVybmFsIElUIGFuZCAzcmQgUGFydGllcyIsIlNhZ2UgUGVvcGxlIiwiZ3JhZmFuYV9zZWN1cml0eV9yZWFkb25seSIsIkRhdGFkb2cgUHJvZHVjdGlvbiIsIkdvb2dsZSBXb3Jrc3BhY2UiLCJHaXRodWIgLSByZWdlbnRtYXJrZXRzIG9yZyIsIkdlbmVyYWwiLCJEYXRhZG9nIFFBIiwiTGFzdFBhc3MiLCJHaXRodWIgLSBiaW5hcnktY29tIG9yZyIsIkJhY2tPZmZpY2UgQ2VsbCJdfQ.Twu-ZbvTxscbUdFooYi6hu3jZCjyBm8zwqIrIwm271JF_g2N2iPFeypnhmNdQisXOQpj4t7D8MFDcQY-IaWF5azObgyBqwBu4Chm7vc3heRMboOeTIXtkaQkRmVCle8TP8y2pyvBgKzSwDF3xRKASIApTrOLQ7EsIXFtPImmtB7Y23Y2NvZfWTj6rKcwly5y_umI3rPzDYwj8E6QUAm2QTQ0DXFqsrrRaKHnUA74Z534J4HY0HHHtVnDRyMRRFMU4_ZoMoUL1yNc2iz0im-qsaecwbBDR7L9jeKKJKjuAE6IKdkTFxeqy295nyLT3PJM4B4IBGDhG5XgnJUGHIAy-Q"

	for i := 0; i < b.N; i++ {
		token, err := jwt.Parse(tokenString, client.GetKeyFunc())
		if err != nil {
			//	b.Fatalf("Error decoding token with GetKeyFunc: %v", err)
		}

		if !token.Valid {
			//	b.Fatalf("Invalid token with GetKeyFunc")
		}
	}
}
