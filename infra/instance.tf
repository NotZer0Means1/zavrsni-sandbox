###############################################################################
# EC2 instanca
###############################################################################

resource "aws_instance" "sandbox" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.sandbox.id]
  iam_instance_profile   = aws_iam_instance_profile.sandbox.name

  # Obavezan IMDSv2: dohvat metapodataka zahtijeva token, a hop limit 1
  # sprjecava da se do metapodataka dode preko preusmjerenog zahtjeva iz
  # kontejnera. Ovo je izravna mjera protiv scenarija S3-01.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = file("${path.module}/user_data.sh")

  tags = {
    Name    = "${var.project}-ec2"
    Project = var.project
  }
}

output "instance_public_ip" {
  value       = aws_instance.sandbox.public_ip
  description = "Javna IP adresa instance za SSH pristup."
}

output "ssh_command" {
  value = "ssh ubuntu@${aws_instance.sandbox.public_ip}"
}

output "log_group" {
  value = aws_cloudwatch_log_group.sandbox.name
}
