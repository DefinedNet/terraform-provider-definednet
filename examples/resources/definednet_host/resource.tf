resource "definednet_host" "lighthouse" {
  network_id       = definednet_network.main.id
  name             = "lighthouse-ams"
  role_id          = definednet_role.lighthouse.id
  is_lighthouse    = true
  ipv4_address     = cidrhost(definednet_network.main.ipv4_cidr, 10)
  static_addresses = ["203.0.113.10:4242", "lighthouse-ams.example.com:4242"]
  listen_port      = 4242
  tags             = ["site:ams"]

  config_overrides = [
    { key = "lighthouse.serve_dns", value = jsonencode(true) },
  ]

  # A new AMI means a new machine, and a machine enrolls only with an unused
  # code, so the change mints one. The host record and its addresses stay.
  enrollment_code_triggers = { ami = data.aws_ami.ubuntu.id }
}

resource "aws_instance" "lighthouse" {
  ami = data.aws_ami.ubuntu.id
  user_data = templatefile("${path.module}/cloud-init.yaml", {
    enrollment_code = definednet_host.lighthouse.enrollment_code
  })
  # Cloud-init runs only on first boot, so a new code needs a new instance.
  user_data_replace_on_change = true
}
