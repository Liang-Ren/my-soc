data "aws_availability_zones" "available" {}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_prefix}-vpc"
    Project = var.project_prefix
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name    = "${var.project_prefix}-igw"
    Project = var.project_prefix
  }
}

resource "aws_subnet" "public" {
  for_each = {
    az1 = { cidr = var.public_subnet_cidrs[0], az = data.aws_availability_zones.available.names[0] }
    az2 = { cidr = var.public_subnet_cidrs[1], az = data.aws_availability_zones.available.names[1] }
  }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_prefix}-public-${each.key}"
    Project = var.project_prefix
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name    = "${var.project_prefix}-public-rt"
    Project = var.project_prefix
  }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  name        = "${var.project_prefix}-alb-sg"
  description = "ALB security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_http_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_prefix}-alb-sg"
    Project = var.project_prefix
  }
}

resource "aws_security_group" "web" {
  name        = "${var.project_prefix}-web-sg"
  description = "Web server SG (behind ALB)"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_prefix}-web-sg"
    Project = var.project_prefix
  }
}

resource "aws_lb" "web" {
  name               = "${var.project_prefix}-alb"
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public : s.id]
  security_groups    = [aws_security_group.alb.id]

  tags = {
    Name    = "${var.project_prefix}-alb"
    Project = var.project_prefix
  }
}

resource "aws_lb_target_group" "web" {
  name     = "${var.project_prefix}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 15
    timeout             = 5
    matcher             = "200-399"
  }

  tags = {
    Name    = "${var.project_prefix}-tg"
    Project = var.project_prefix
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true

  owners = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "web" {
  count         = 2
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  subnet_id     = element(values(aws_subnet.public)[*].id, count.index)
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile    = aws_iam_instance_profile.web_instance.name

  user_data = <<-EOF
              #!/bin/bash

              # Install Apache and CloudWatch Agent (Amazon Linux 2023)
              dnf install -y httpd amazon-cloudwatch-agent || yum install -y httpd amazon-cloudwatch-agent

              # Simple web page
              echo "hello, Liang from my-soc." > /var/www/html/index.html
              systemctl enable httpd
              systemctl start httpd

              # CloudWatch Agent configuration for OS and Apache logs
              cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'AGENTCFG'
              {
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/messages",
                          "log_group_name": "${aws_cloudwatch_log_group.web_os.name}",
                          "log_stream_name": "{instance_id}-os"
                        },
                        {
                          "file_path": "/var/log/httpd/access_log",
                          "log_group_name": "${aws_cloudwatch_log_group.web_app.name}",
                          "log_stream_name": "{instance_id}-access"
                        },
                        {
                          "file_path": "/var/log/httpd/error_log",
                          "log_group_name": "${aws_cloudwatch_log_group.web_app.name}",
                          "log_stream_name": "{instance_id}-error"
                        }
                      ]
                    }
                  }
                },
                "agent": {
                  "run_as_user": "root"
                }
              }
              AGENTCFG

              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a fetch-config -m ec2 \
                -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
                -s
              EOF

  tags = {
    Name    = "${var.project_prefix}-web-${count.index}"
    Project = var.project_prefix
  }
}

resource "aws_lb_target_group_attachment" "web" {
  count            = 2
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web[count.index].id
  port             = 80
}
