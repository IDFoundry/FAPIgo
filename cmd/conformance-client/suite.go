package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// suitePlan is the minimal shape this driver needs back from POST
// /api/plan — the plan's id, and every module the plan wants run, in
// the order the suite itself lists them.
type suitePlan struct {
	ID      string `json:"id"`
	Modules []struct {
		TestModule string `json:"testModule"`
	} `json:"modules"`
}

// suiteModule is the minimal shape this driver needs back from POST
// /api/runner: the module's own id, and the base URL
// (https://.../test/a/<alias>) its discovery document, authorization
// endpoint, etc. all live under.
type suiteModule struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// createPlan creates a new conformance-suite test plan for planName
// (with any [variant=value] selectors already embedded, matching how
// run-test-plan.py's own CLI syntax works), posting configJSON as the
// plan configuration body, and returns the new plan's id and the full
// list of module names it wants run, in the suite's own order.
func createPlan(httpClient *http.Client, apiBase, planName string, variant map[string]string, configJSON []byte) (string, []string, error) {
	q := url.Values{}
	q.Set("planName", planName)
	if len(variant) > 0 {
		variantJSON, err := json.Marshal(variant)
		if err != nil {
			return "", nil, fmt.Errorf("marshal variant: %w", err)
		}
		q.Set("variant", string(variantJSON))
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"api/plan?"+q.Encode(), bytes.NewReader(configJSON))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	body, status, err := do(httpClient, req)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusCreated {
		return "", nil, fmt.Errorf("create plan: unexpected status %d: %s", status, body)
	}
	var plan suitePlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return "", nil, fmt.Errorf("decode plan response: %w", err)
	}
	names := make([]string, len(plan.Modules))
	for i, m := range plan.Modules {
		names[i] = m.TestModule
	}
	return plan.ID, names, nil
}

// createModuleInstance creates one test module instance within planID
// and returns its id and base URL.
func createModuleInstance(httpClient *http.Client, apiBase, planID, testName string) (suiteModule, error) {
	q := url.Values{}
	q.Set("test", testName)
	q.Set("plan", planID)

	req, err := http.NewRequest(http.MethodPost, apiBase+"api/runner?"+q.Encode(), nil)
	if err != nil {
		return suiteModule{}, err
	}

	body, status, err := do(httpClient, req)
	if err != nil {
		return suiteModule{}, err
	}
	if status != http.StatusCreated {
		return suiteModule{}, fmt.Errorf("create module instance: unexpected status %d: %s", status, body)
	}
	var module suiteModule
	if err := json.Unmarshal(body, &module); err != nil {
		return suiteModule{}, fmt.Errorf("decode module response: %w", err)
	}
	return module, nil
}

// suiteRunnerStatus is the shape GET /api/runner/{id} returns — notably
// "exposed", the same "exported values" a human operator reads from the
// suite's own web frontend to learn a value the module generated at
// runtime and has no standard-discovery home, e.g. a profile-specific
// resource endpoint URL (GET /api/info/{id}, by contrast, never carries
// this — confirmed by reading both responses side by side against a
// live module instance, not assumed from the field name alone).
type suiteRunnerStatus struct {
	Exposed map[string]string `json:"exposed"`
}

// fetchExposedValues returns moduleID's current "exported values" map.
func fetchExposedValues(httpClient *http.Client, apiBase, moduleID string) (map[string]string, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/runner/"+moduleID, nil)
	if err != nil {
		return nil, err
	}
	body, status, err := do(httpClient, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("fetch exposed values: unexpected status %d: %s", status, body)
	}
	var runnerStatus suiteRunnerStatus
	if err := json.Unmarshal(body, &runnerStatus); err != nil {
		return nil, fmt.Errorf("decode runner status: %w", err)
	}
	return runnerStatus.Exposed, nil
}

// moduleInfo is the minimal shape this driver needs from GET
// /api/info/{id} — the module's current lifecycle status, and its
// graded result once that status is final. Result is meaningless while
// Status isn't yet FINISHED or INTERRUPTED — the suite leaves a stale
// default in that field until then, confirmed live (see
// waitUntilFinished's doc comment), not assumed from the field's mere
// presence.
type moduleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// waitUntilWaiting polls GET /api/info/{moduleID} until the module
// reaches WAITING, the state in which it's actually ready to receive
// the RP's first request. A module instance is not immediately usable
// right after creation — the suite still has async setup to do (server
// configuration, JWKS generation) — and firing a request at it too
// early doesn't just fail harmlessly: the module treats the unexpected
// early arrival as if it belonged to a later step, gets stuck
// (INTERRUPTED with "Illegal test state change"), and can never recover
// for the rest of its run. Discovered the hard way driving this exact
// module, not assumed.
func waitUntilWaiting(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		req, err := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
		if err != nil {
			return err
		}
		body, status, err := do(httpClient, req)
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			var info moduleInfo
			if err := json.Unmarshal(body, &info); err == nil && info.Status == "WAITING" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("module %s did not reach WAITING within %s", moduleID, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitUntilFinished polls GET /api/info/{moduleID} until its status is
// FINISHED or INTERRUPTED (or timeout elapses), then returns that
// status and its now-meaningful Result — a module can legitimately sit
// in WAITING for a few extra seconds after this driver's own last
// request (see AbstractFAPI2SPFinalClientTest's waitTimeoutSeconds
// grace period, default 5s, for any additional unexpected request
// before it auto-finishes a module that completed normally).
func waitUntilFinished(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (status, result string, err error) {
	deadline := time.Now().Add(timeout)
	for {
		req, reqErr := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
		if reqErr != nil {
			return "", "", reqErr
		}
		body, httpStatus, doErr := do(httpClient, req)
		if doErr != nil {
			return "", "", doErr
		}
		if httpStatus == http.StatusOK {
			var info moduleInfo
			if err := json.Unmarshal(body, &info); err == nil {
				if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
					return info.Status, info.Result, nil
				}
				status = info.Status
			}
		}
		if time.Now().After(deadline) {
			return status, "", fmt.Errorf("module %s did not finish within %s", moduleID, timeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func do(httpClient *http.Client, req *http.Request) (body []byte, status int, err error) {
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read response body: %w", err)
	}
	return body, res.StatusCode, nil
}
