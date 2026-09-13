terraform {
  required_providers {
    fleet = {
      source = "kforbus3/provenance"
    }
  }
}

# endpoint can also come from PROV_URL, token from PROV_API_TOKEN.
provider "fleet" {
  endpoint = "https://provenance.example.com"
  # token  = "flt_..."   # prefer the PROV_API_TOKEN environment variable
}

# A managed host.
resource "prov_host" "web" {
  hostname    = "web-01"
  environment = "production"
  owner       = "platform"
  ssh_user    = "fleet"
  tags        = ["web", "prod"]
}

# A dynamic group whose membership follows host tags (omit `rule` for a static group).
resource "prov_group" "prod_web" {
  name        = "prod-web"
  description = "Production web tier"
  rule {
    environment = "production"
    tags_all    = ["web"]
  }
}

# Look up a role by name to grant it to a service account.
data "prov_role" "operator" {
  name = "Operator"
}

# A service account for CI, plus a scoped, expiring token.
resource "prov_service_account" "ci" {
  username     = "ci-bot"
  display_name = "CI pipeline"
  role_ids     = [data.prov_role.operator.id]
}

resource "prov_service_account_token" "ci" {
  service_account_id = prov_service_account.ci.id
  name               = "gitlab-ci"
  expires_in_days    = 90
}

output "ci_token" {
  description = "Bearer token for the CI service account (store securely)."
  value       = prov_service_account_token.ci.token
  sensitive   = true
}
