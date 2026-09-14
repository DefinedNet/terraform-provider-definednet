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
	planChecks         []plancheck.PlanCheck
}

// runUnitTest runs steps against the fake API (nil means no provider block is
// prepended, for provider-configuration tests).
func runUnitTest(t *testing.T, f *fakeAPI, steps []testStep) {
	t.Helper()
	prefix := ""
	if f != nil {
		prefix = providerConfig(f)
	}

	tfSteps := make([]resource.TestStep, 0, len(steps))
	for _, s := range steps {
		step := resource.TestStep{}
		if s.importState {
			step.ResourceName = s.importResource
			step.ImportState = true
			step.ImportStateVerify = true
			step.ImportStateVerifyIgnore = s.importVerifyIgnore
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

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps:                    tfSteps,
	})
}
