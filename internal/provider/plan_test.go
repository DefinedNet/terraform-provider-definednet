package provider

import (
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

func expectReplace(addr string) []plancheck.PlanCheck {
	return []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)}
}

func expectUpdate(addr string) []plancheck.PlanCheck {
	return []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)}
}

func expectCreate(addr string) []plancheck.PlanCheck {
	return []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionCreate)}
}
