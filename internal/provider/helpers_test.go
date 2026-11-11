package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// testStep is a compact description of a resource.TestStep.
type testStep struct {
	config             string
	checks             []resource.TestCheckFunc
	expectError        string
	importState        bool
	importResource     string
	importVerifyIgnore []string
	// importPersist keeps the imported state for the following steps so they
	// exercise a resource whose state came from import, not from create.
	importPersist bool
	// importStateID imports this ID instead of the one Terraform created.
	importStateID string
	planChecks    []plancheck.PlanCheck
	destroy       bool
	// preConfig runs before the step, for changes made behind Terraform's back.
	preConfig func()
}

// runUnitTest runs steps against the fake API (nil means no provider block is
// prepended, for provider-configuration tests).
func runUnitTest(t *testing.T, f *fakeAPI, steps []testStep) {
	t.Helper()
	prefix := ""
	if f != nil {
		prefix = providerConfig(f)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps:                    buildSteps(prefix, steps),
	})
}

// buildSteps prepends prefix, a provider block or nothing, to every config.
func buildSteps(prefix string, steps []testStep) []resource.TestStep {
	tfSteps := make([]resource.TestStep, 0, len(steps))
	for _, s := range steps {
		step := resource.TestStep{PreConfig: s.preConfig, Destroy: s.destroy}
		if s.importState {
			step.ResourceName = s.importResource
			step.ImportState = true
			// A fresh import has no prior state to verify against.
			step.ImportStateVerify = s.importStateID == ""
			step.ImportStateVerifyIgnore = s.importVerifyIgnore
			step.ImportStatePersist = s.importPersist
			step.ImportStateId = s.importStateID
			if s.importStateID != "" {
				// Import into an empty state needs the resource block to exist.
				step.Config = prefix + s.config
			}
		} else {
			step.Config = prefix + s.config
			step.Check = resource.ComposeAggregateTestCheckFunc(s.checks...)
		}
		if s.expectError != "" {
			step.ExpectError = regexp.MustCompile(s.expectError)
		}
		if len(s.planChecks) > 0 {
			step.ConfigPlanChecks = resource.ConfigPlanChecks{PreApply: s.planChecks}
		}
		tfSteps = append(tfSteps, step)
	}
	return tfSteps
}

// runRemovedOutOfBandTest applies cfg, calls remove to delete the object
// behind Terraform's back, and expects the next plan to recreate it rather
// than fail the refresh.
func runRemovedOutOfBandTest(t *testing.T, f *fakeAPI, cfg, addr string, remove func()) {
	t.Helper()
	cfg = providerConfig(f) + cfg
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig: func() {
					f.mu.Lock()
					defer f.mu.Unlock()
					remove()
				},
				Config:           cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: expectCreate(addr)},
			},
		},
	})
}
