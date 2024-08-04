locals {
  domain      = "cridland.io"
  hostname    = "cassidy"
  public_fqdn = "${local.hostname}.${local.domain}"
}

resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.private_key.private_key_pem
  email_address   = "dave+metre@cridland.net"
}

resource "acme_certificate" "certificate" {
  account_key_pem           = acme_registration.reg.account_key_pem
  common_name               = local.public_fqdn
  subject_alternative_names = [local.public_fqdn]

  dns_challenge {
    provider = "gandiv5"
  }
}

resource "local_file" "pkey" {
  filename = "../private_key.pem"
  content  = acme_certificate.certificate.private_key_pem
}

resource "local_file" "cert" {
  filename = "../public_key.pem"
  content  = acme_certificate.certificate.certificate_pem
}

resource "gandi_livedns_record" "hostname" {
  name   = local.hostname
  ttl    = 3600
  type   = "A"
  values = ["217.155.137.60"]
  zone   = data.gandi_livedns_domain.zone.name
}

data "gandi_livedns_domain" "zone" {
  name = local.domain
}
