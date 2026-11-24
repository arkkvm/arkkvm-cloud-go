package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"log/slog"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"arkkvm.com/arkkvm-cloud/internal/model"
	"arkkvm.com/arkkvm-cloud/internal/pkg"
	"arkkvm.com/arkkvm-cloud/internal/repository"
)

// ReleaseRetrieveVO is the raw (unwrapped) response of GET /releases.
// Fields stay null when no update applies — matching the legacy Jackson
// output of the partially-filled builder.
type ReleaseRetrieveVO struct {
	AppVersion        *string `json:"appVersion"`
	AppURL            *string `json:"appUrl"`
	AppHashSignature  *string `json:"appHashSignature"`
	AppSummary        *string `json:"appSummary"`
	SystemVersion     *string `json:"systemVersion"`
	SystemURL         *string `json:"systemUrl"`
	SystemHashSignature *string `json:"systemHashSignature"`
	SystemSummary     *string `json:"systemSummary"`
}

type ReleaseService struct {
	releases    *repository.ReleaseRepo
	signer      *Signer
	downloadCDN string
}

func NewReleaseService(releases *repository.ReleaseRepo, signer *Signer, downloadCDN string) *ReleaseService {
	return &ReleaseService{releases: releases, signer: signer, downloadCDN: downloadCDN}
}

// Retrieve implements the deployed-branch semantics (doc 02 §1.4):
// strict three-segment version compare against the structured
// major/minor/patch columns, plus distribution gating.
func (s *ReleaseService) Retrieve(ctx context.Context, appVersion, systemVersion, encryptedDeviceID string) (*ReleaseRetrieveVO, error) {
	// Decrypt the deviceId (RSA-OAEP + base64url). On failure the legacy code
	// falls back to the raw value; distribution gates that require a stable
	// device identity will simply not match.
	deviceID := encryptedDeviceID
	if deviceID != "" {
		if plain, err := s.signer.DecryptDeviceID(deviceID); err == nil {
			deviceID = plain
		} else {
			// Same fallback as the legacy code, but surfaced: a decrypt
			// failure silently disables internal/gray distribution for the
			// device and is otherwise undetectable server-side.
			slog.Warn("release: decrypt deviceId failed, falling back to raw value", "error", err)
		}
	}

	currentApp, err := pkg.ParseVersion(appVersion)
	if err != nil {
		return nil, err
	}
	currentSystem, err := pkg.ParseVersion(systemVersion)
	if err != nil {
		return nil, err
	}

	vo := &ReleaseRetrieveVO{}
	appRelease, err := s.latestEligible("app", currentApp, deviceID)
	if err != nil {
		return nil, err
	}
	if appRelease != nil {
		sig, err := s.signer.Sign(appRelease.Hash)
		if err != nil {
			return nil, err
		}
		vo.AppVersion = &appRelease.Version
		url := s.downloadCDN + appRelease.URL
		vo.AppURL = &url
		vo.AppHashSignature = &sig
		vo.AppSummary = appRelease.Summary
	}

	systemRelease, err := s.latestEligible("system", currentSystem, deviceID)
	if err != nil {
		return nil, err
	}
	if systemRelease != nil {
		sig, err := s.signer.Sign(systemRelease.Hash)
		if err != nil {
			return nil, err
		}
		vo.SystemVersion = &systemRelease.Version
		url := s.downloadCDN + systemRelease.URL
		vo.SystemURL = &url
		vo.SystemHashSignature = &sig
		vo.SystemSummary = systemRelease.Summary
	}
	return vo, nil
}

// latestEligible walks the type's releases newest-first and returns the first
// entry that is both newer than the reported version and distributable.
func (s *ReleaseService) latestEligible(releaseType string, current pkg.Version, deviceID string) (*model.Release, error) {
	list, err := s.releases.ListByTypeOrdered(releaseType)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	for i := range list {
		r := &list[i]
		target := pkg.Version{Major: r.Major, Minor: r.Minor, Patch: r.Patch}
		if pkg.Compare(current, target) == -1 && canDistribute(r, deviceID) {
			return r, nil
		}
	}
	return nil, nil
}

// canDistribute applies the distribution rules of the deployed branch:
//
//	3 full rollout: always allowed;
//	1 internal:     only for devices listed in device_sns;
//	2 gray rollout: stable MD5 bucketing of the device SN against gray%.
//
// Rules 1 and 2 require a (decrypted) deviceId; without one nothing but full
// rollouts are distributable.
func canDistribute(r *model.Release, deviceID string) bool {
	if r.Distribution == nil {
		return false
	}
	switch *r.Distribution {
	case 3:
		return true
	case 1:
		if deviceID == "" || r.DeviceSNs == nil || *r.DeviceSNs == "" {
			return false
		}
		for _, sn := range strings.Split(*r.DeviceSNs, ",") {
			if strings.TrimSpace(sn) == deviceID {
				return true
			}
		}
		return false
	case 2:
		if deviceID == "" || r.Gray == nil {
			return false
		}
		return grayBucket(deviceID) < *r.Gray
	default:
		return false
	}
}

// grayBucket maps a device SN to a stable bucket in [0,100): the first 8 hex
// digits of MD5(SN) parsed as a number, modulo 100. Byte-identical to the
// legacy isDeviceEligibleForLatestRelease arithmetic.
func grayBucket(deviceSN string) int {
	sum := md5.Sum([]byte(deviceSN))
	hashed := hex.EncodeToString(sum[:])
	value, err := strconv.ParseUint(hashed[:8], 16, 64)
	if err != nil {
		return 0
	}
	return int(value % 100)
}
