terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "AWS_PRIVATE_KEY" {
  type = string
}

variable "GIT_TOKEN" {
  type = string
}

variable "GIT_USER" {
  type = string
}

# Creating VPC
resource "aws_vpc" "miniproject-vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "miniproject-vpc"
  }
}

# Create Internet Gateway

resource "aws_internet_gateway" "miniproject_igw" {
  vpc_id = aws_vpc.miniproject-vpc.id
  tags = {
    Name = "miniproject_igw"
  }
}

# Creating Public Route Table
resource "aws_route_table" "miniproject_public_route_table" {
  vpc_id = aws_vpc.miniproject-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.miniproject_igw.id
  }
  tags = {
    Name = "miniproject_public_route_table"
  }
}

# Associating public subnet 1 with public route table

resource "aws_route_table_association" "miniproject_public_subnet_one_assoc" {
  subnet_id      = aws_subnet.miniproject_public_subnet_one.id
  route_table_id = aws_route_table.miniproject_public_route_table.id
}

# Associate public subnet 2 with public route table

resource "aws_route_table_association" "miniproject_public_subnet_one_assoc" {
  subnet_id      = aws_subnet.miniproject_public_subnet_two.id
  route_table_id = aws_route_table.miniproject_public_route_table.id
}

# Creating Public Subnet-1
resource "aws_subnet" "miniproject_public_subnet_one" {
  vpc_id                  = aws_vpc.miniproject-vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"
  tags = {
    Name = "miniproject_public_subnet_one"
  }
}
# Creating Public Subnet-2
resource "aws_subnet" "miniproject_public_subnet_two" {
  vpc_id                  = aws_vpc.miniproject-vpc.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1b"
  tags = {
    Name = "miniproject_public_subnet_two"
  }
}

# Creating Public Subnet-3
resource "aws_subnet" "miniproject_private_subnet_three" {
  vpc_id                  = aws_vpc.miniproject-vpc.id
  cidr_block              = "10.0.3.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "us-east-1c"
  tags = {
    Name = "miniproject_private_subnet_three"
  }
}
resource "aws_network_acl" "miniproject_network_acl" {
  vpc_id     = aws_vpc.miniproject-vpc.id
  subnet_ids = [aws_subnet.miniproject_public_subnet_one.id, aws_subnet.miniproject_public_subnet_two.id]

  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

# Create a security group for the load balancer

resource "aws_security_group" "miniproject_load_balance_security_group" {
  name        = "miniproject_load_balance_security_group"
  description = "Security group for the load balancer"
  vpc_id      = aws_vpc.miniproject-vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create Security Group to allow port 22, 80 and 443

resource "aws_security_group" "miniproject_security_group_rule" {
  name        = "allow_ssh_http_https"
  description = "Allow SSH, HTTP and HTTPS inbound traffic for private instances"
  vpc_id      = aws_vpc.miniproject-vpc.id
  ingress {
    description     = "HTTP"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
    security_groups = [aws_security_group.miniproject_load_balance_security_group.id]
  }
  ingress {
    description     = "HTTPS"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
    security_groups = [aws_security_group.miniproject_load_balance_security_group.id]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }
  tags = {
    Name = "miniproject_security_group_rule"
  }
}

# creating instance 1

resource "aws_instance" "serverOne" {
  ami               = "ami-0aa7d40eeae50c9a9"
  instance_type     = "t2.micro"
  key_name          = "miniproject"
  security_groups   = [aws_security_group.miniproject_security_group_rule.id]
  subnet_id         = aws_subnet.miniproject_public_subnet_one.id
  availability_zone = "us-east-1a"
  tags = {
    Name   = "miniproject-terraform-one"
    source = "terraform"
  }
}

# creating instance 2

resource "aws_instance" "serverTwo" {
  ami               = "ami-0aa7d40eeae50c9a9"
  instance_type     = "t2.micro"
  key_name          = "miniproject"
  security_groups   = [aws_security_group.miniproject_security_group_rule.id]
  subnet_id         = aws_subnet.miniproject_public_subnet_two.id
  availability_zone = "us-east-1b"
  tags = {
    Name   = "miniproject-terraform-two"
    source = "terraform"
  }
}

# creating instance 3

resource "aws_instance" "serverThree" {
  ami               = "ami-0aa7d40eeae50c9a9"
  instance_type     = "t2.micro"
  key_name          = "miniproject"
  security_groups   = [aws_security_group.miniproject_security_group_rule.id]
  subnet_id         = aws_subnet.miniproject_public_subnet_one.id
  availability_zone = "us-east-1a"
  tags = {
    Name   = "miniproject-terraform-three"
    source = "terraform"
  }
}


resource "aws_instance" "miniproject_ansible_master" {
  ami               = "ami-0aa7d40eeae50c9a9"
  instance_type     = "t2.micro"
  key_name          = "miniproject"
  security_groups   = [aws_security_group.miniproject_security_group_rule.id]
  subnet_id         = aws_subnet.miniproject_public_subnet_one.id
  availability_zone = "us-east-1a"
  tags = {
    Name   = "miniproject-ansible-master "
  }
  
  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = "${var.AWS_PRIVATE_KEY}"
    host        = "${self.public_ip}"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo amazon-linux-extras install ansible2 -y",
      "sudo yum install git -y",
      "git clone https://${var.GIT_USER}:${var.GIT_TOKEN}@github.com/Asterisk-z/miniproject-terraform.git /tmp/miniproject-terraform",
      "echo '${aws_instance.serverOne.public_ip}\n${aws_instance.serverTwo.public_ip}\n${aws_instance.serverThree.public_ip}' >> /tmp/miniproject-terraform/host-inventory",
      "echo '${var.AWS_PRIVATE_KEY}' >> /tmp/miniproject-terraform/miniproject.pem",
      "chmod 400 /tmp/miniproject-terraform/miniproject.pem",
      "sleep 120; cd /tmp/miniproject-terraform; ansible-playbook -i host-inventory ansible.yml -v",
      "sudo shutdown -k now"
    ]
  }
}

# Create a file to store the IP addresses of the instances
resource "local_file" "Ip_address" {
  filename = "host-inventory"
  content  = <<EOT
${aws_instance.serverOne.public_ip}
${aws_instance.serverTwo.public_ip}
${aws_instance.serverThree.public_ip}
  EOT
}

# Create an Application Load Balancer

resource "aws_lb" "miniproject_load_balancer" {
  name               = "miniproject_load_balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.miniproject_load_balance_security_group.id]
  subnets            = [aws_subnet.miniproject_public_subnet_one.id, aws_subnet.miniproject_public_subnet_two.id]

  #enable_cross_zone_load_balancing = true
  enable_deletion_protection = false
  depends_on                 = [aws_instance.serverOne, aws_instance.serverTwo, aws_instance.serverThree]
}

# Create the target group

resource "aws_lb_target_group" "miniproject_target_group" {
  name        = "miniproject_target_group"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.miniproject-vpc.id
  health_check {
    path                = "/"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 15
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

# Create the listener

resource "aws_lb_listener" "miniproject-listener" {
  load_balancer_arn = aws_lb.miniproject_load_balancer.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.miniproject_target_group.arn
  }
}
# Create the listener rule
resource "aws_lb_listener_rule" "miniproject-listener-rule" {
  listener_arn = aws_lb_listener.miniproject-listener.arn
  priority     = 1
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.miniproject_target_group.arn
  }
  condition {
    host_header {
      values = ["miniproject.danasterisk.me"]
    }
  }
}

# Attach the target group to the load balancer

resource "aws_lb_target_group_attachment" "miniproject_target_group-attachment1" {
  target_group_arn = aws_lb_target_group.miniproject_target_group.arn
  target_id        = aws_instance.serverOne.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "miniproject_target_group-attachment2" {
  target_group_arn = aws_lb_target_group.miniproject_target_group.arn
  target_id        = aws_instance.serverTwo.id
  port             = 80
}
resource "aws_lb_target_group_attachment" "miniproject_target_group-attachment3" {
  target_group_arn = aws_lb_target_group.miniproject_target_group.arn
  target_id        = aws_instance.serverThree.id
  port             = 80

}


// Load balancer outputs
output "vpc_id" {
  description = "VPC"
  value       = aws_vpc.mini-project-vpc.id
}

output "public_ip1" {
  description = "server one public ip"
  value       = aws_instance.mini-project-1.public_ip
}
output "public_ip2" {
  description = "server two public ip"
  value       = aws_instance.mini-project-2.public_ip
}
output "public_ip3" {
  description = "server two public ip"
  value       = aws_instance.mini-project-3.public_ip
}

variable "domain_name" {
  default     = "danasterisk.me"
  type        = string
}
# get hosted zone details
resource "aws_route53_zone" "hosted_zone" {
  name = var.domain_name
  tags = {
    Environment = "dev"
  }
}
# create a record set in route 53

# terraform aws route 53 record
resource "aws_route53_record" "site_domain" {
  zone_id = aws_route53_zone.hosted_zone.zone_id
  name    = "miniproject.${var.domain_name}"
  type    = "A"
  alias {
    name                   = aws_lb.miniproject_load_balancer.dns_name
    zone_id                = aws_lb.miniproject_load_balancer.zone_id
    evaluate_target_health = true
  }
}