terraform {
  backend "s3" {
    bucket = "dwd-tfstate"
    key    = "metre/tfstate"
    region = "eu-west-2"
  }
  required_providers {
    gandi = {
      version = "~> 2.0.0"
      source  = "go-gandi/gandi"
    }
    acme = {
      version = "~> 2.0"
      source  = "vancluever/acme"
    }
  }
}

provider "acme" {
  server_url = "https://acme-v02.api.letsencrypt.org/directory"
}
