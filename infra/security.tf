###############################################################################
# Sigurnosna skupina i IAM uloga
#
# Sigurnosna skupina dopusta samo SSH s navedene adrese. Izlazni promet je
# ogranicen na HTTPS (dohvat Docker slika i paketa pri postavljanju) te DNS.
# Time se na razini mreze onemogucuje eksfiltracija iz same instance, dok se
# izlaz iz pojedinog izvrsnog okruzenja dodatno blokira postavkom network_mode
# = none na razini kontejnera.
###############################################################################

resource "aws_security_group" "sandbox" {
  name        = "${var.project}-sg"
  description = "Ocvrsnuta skupina za sandbox instancu"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH samo s vlastite adrese"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_ingress_cidr]
  }

  egress {
    description = "HTTPS za dohvat slika i paketa"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP za apt repozitorije (Ubuntu arhive idu preko porta 80)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = var.project }
}

# IAM uloga instance: namjerno bez ijedne ovlasti nad AWS uslugama osim
# zapisivanja u CloudWatch Logs. Cak i ako napadac dohvati vjerodajnice uloge
# preko metapodataka, njima ne moze nauditi ostatku racuna.
resource "aws_iam_role" "sandbox" {
  name = "${var.project}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Project = var.project }
}

resource "aws_iam_role_policy" "logs_only" {
  name = "${var.project}-logs-only"
  role = aws_iam_role.sandbox.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.sandbox.arn}:*"
    }]
  })
}

resource "aws_iam_instance_profile" "sandbox" {
  name = "${var.project}-profile"
  role = aws_iam_role.sandbox.name
}

resource "aws_cloudwatch_log_group" "sandbox" {
  name              = "/${var.project}/audit"
  retention_in_days = 14
  tags              = { Project = var.project }
}
