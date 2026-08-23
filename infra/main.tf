###############################################################################
# Izolirano cloud okruzenje za izvrsavanje koda AI agenata
#
# Postavlja jednu EC2 instancu u eu-central-1 na kojoj se pokrecu Docker, gVisor
# i sam sustav. Konfiguracija je namjerno ocvrsnuta:
#   - obavezan IMDSv2 uz hop limit 1 (otezava krada vjerodajnica preko SSRF-a)
#   - sigurnosna skupina bez ikakvog izlaznog prometa osim nuznog za postavljanje
#   - IAM uloga s najmanjim mogucim ovlastima (samo zapisivanje logova)
#
# Ovo okruzenje sluzi iskljucivo za testiranje ovog rada.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "instance_type" {
  type    = string
  default = "m7i.large" # 2 vCPU, 8 GB RAM: runc + gVisor + model llama3.1 (8B)
}

variable "ssh_ingress_cidr" {
  type        = string
  description = "CIDR s kojeg je dopusten SSH. Postaviti na vlastitu IP adresu /32."
  # namjerno bez zadane vrijednosti da se ne otvori 0.0.0.0/0 nehotice
}

variable "key_name" {
  type        = string
  description = "Ime postojeceg EC2 key para za SSH pristup."
}

variable "project" {
  type    = string
  default = "zavrsni-sandbox"
}

# Najnovija Ubuntu 22.04 LTS slika (Canonical).
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Zadani VPC i podmreza; za rad je dovoljno, produkcija bi trazila izdvojeni VPC.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
