terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Lets the patched ("fix") stack coexist in the same account/region as the
# original vulnerable deployment, which uses these same base names with no
# suffix at all - every account/globally-unique resource name below is
# suffixed with this so the two can be applied side by side for the
# before/after comparison.
variable "suffix" {
  type    = string
  default = "fix"
}

# Remediation: RDS master password is generated at apply time instead of being
# hardcoded in source. It is stored only in Terraform state and in Secrets Manager.
resource "random_password" "rds_master" {
  length  = 24
  special = false
}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC Config for public access
resource "aws_vpc" "lab-vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "AWS_GOAT_VPC"
  }
}
resource "aws_subnet" "lab-subnet-public-1" {
  vpc_id                  = aws_vpc.lab-vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
}
resource "aws_internet_gateway" "my_vpc_igw" {
  vpc_id = aws_vpc.lab-vpc.id
  tags = {
    Name = "My VPC - Internet Gateway"
  }
}
resource "aws_route_table" "my_vpc_us_east_1_public_rt" {
  vpc_id = aws_vpc.lab-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.my_vpc_igw.id
  }

  tags = {
    Name = "Public Subnet Route Table."
  }
}

resource "aws_route_table_association" "my_vpc_us_east_1a_public" {
  subnet_id      = aws_subnet.lab-subnet-public-1.id
  route_table_id = aws_route_table.my_vpc_us_east_1_public_rt.id
}
resource "aws_subnet" "lab-subnet-public-1b" {
  vpc_id                  = aws_vpc.lab-vpc.id
  cidr_block              = "10.0.128.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
}
resource "aws_route_table_association" "my_vpc_us_east_1b_public" {
  subnet_id      = aws_subnet.lab-subnet-public-1b.id
  route_table_id = aws_route_table.my_vpc_us_east_1_public_rt.id
}

resource "aws_security_group" "ecs_sg" {
  name        = "ECS-SG"
  description = "SG for cluster created from terraform"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer_security_group.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create Database Subnet Group
# terraform aws db subnet group
resource "aws_db_subnet_group" "database-subnet-group" {
  name        = "database-subnets-${var.suffix}"
  subnet_ids  = [aws_subnet.lab-subnet-public-1.id, aws_subnet.lab-subnet-public-1b.id]
  description = "Subnets for Database Instance"

  tags = {
    Name = "Database Subnets"
  }
}

# Create Security Group for the Database
# terraform aws create security group

resource "aws_security_group" "database-security-group" {
  name        = "Database Security Group"
  description = "Enable MYSQL Aurora access on Port 3306"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    description     = "MYSQL/Aurora Access"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = ["${aws_security_group.ecs_sg.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "rds-db-sg"
  }

}

# Create Database Instance Restored from DB Snapshots
# terraform aws db instance
resource "aws_db_instance" "database-instance" {
  identifier             = "aws-goat-db-${var.suffix}"
  allocated_storage      = 10
  instance_class         = "db.t3.micro"
  engine                 = "mysql"
  engine_version         = "8.0"
  username               = "root"
  password               = random_password.rds_master.result
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  availability_zone      = "us-east-1a"
  db_subnet_group_name   = aws_db_subnet_group.database-subnet-group.name
  vpc_security_group_ids = [aws_security_group.database-security-group.id]
}



resource "aws_security_group" "load_balancer_security_group" {
  name        = "Load-Balancer-SG"
  description = "SG for load balancer created from terraform"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    # Restricted to the sandbox pentest machine only; do not open to 0.0.0.0/0
    cidr_blocks = ["191.96.216.174/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "aws-goat-m2-sg"
  }
}



resource "aws_iam_role" "ecs-instance-role" {
  name                 = "ecs-instance-role-${var.suffix}"
  path                 = "/"
  permissions_boundary = aws_iam_policy.instance_boundary_policy.arn
  assume_role_policy = jsonencode({
    "Version" : "2008-10-17",
    "Statement" : [
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_role_policy_attachment" "ecs-instance-role-attachment-1" {
  role       = aws_iam_role.ecs-instance-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}
resource "aws_iam_role_policy_attachment" "ecs-instance-role-attachment-2" {
  role       = aws_iam_role.ecs-instance-role.name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

resource "aws_iam_role_policy_attachment" "ecs-instance-role-attachment-3" {
  role       = aws_iam_role.ecs-instance-role.name
  policy_arn = aws_iam_policy.ecs_instance_policy.arn
}

resource "aws_iam_policy" "ecs_instance_policy" {
  name = "aws-goat-instance-policy-${var.suffix}"
  policy = jsonencode({
    "Statement" : [
      {
        "Action" : [
          "ssm:*",
          "ssmmessages:*",
          "ec2:RunInstances",
          "ec2:Describe*"
        ],
        "Effect" : "Allow",
        "Resource" : "*",
        "Sid" : "Pol1"
      }
    ],
    "Version" : "2012-10-17"
  })
}

resource "aws_iam_policy" "instance_boundary_policy" {
  name = "aws-goat-instance-boundary-policy-${var.suffix}"
  policy = jsonencode({
    "Statement" : [
      {
        "Action" : [
          "iam:List*",
          "iam:Get*",
          "iam:PassRole",
          "iam:PutRole*",
          "ssm:*",
          "ssmmessages:*",
          "ec2:RunInstances",
          "ec2:Describe*",
          "ecs:*",
          "ecr:*",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Effect" : "Allow",
        "Resource" : "*",
        "Sid" : "Pol1"
      }
    ],
    "Version" : "2012-10-17"
  })
}

resource "aws_iam_instance_profile" "ec2-deployer-profile" {
  name = "ec2Deployer-${var.suffix}"
  path = "/"
  role = aws_iam_role.ec2-deployer-role.id
}
resource "aws_iam_role" "ec2-deployer-role" {
  name = "ec2Deployer-role-${var.suffix}"
  path = "/"
  assume_role_policy = jsonencode({
    "Version" : "2008-10-17",
    "Statement" : [
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "ec2_deployer_admin_policy" {
  name = "ec2DeployerAdmin-policy-${var.suffix}"
  policy = jsonencode({
    "Statement" : [
      {
        "Action" : [
          "*"
        ],
        "Effect" : "Allow",
        "Resource" : "*",
        "Sid" : "Policy1"
      }
    ],
    "Version" : "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "ec2-deployer-role-attachment" {
  role       = aws_iam_role.ec2-deployer-role.name
  policy_arn = aws_iam_policy.ec2_deployer_admin_policy.arn
}

resource "aws_iam_instance_profile" "ecs-instance-profile" {
  name = "ecs-instance-profile-${var.suffix}"
  path = "/"
  role = aws_iam_role.ecs-instance-role.id
}
resource "aws_iam_role" "ecs-task-role" {
  name = "ecs-task-role-${var.suffix}"
  path = "/"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ecs-tasks.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "ecs-task-role-attachment" {
  role       = aws_iam_role.ecs-task-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
# Remediation (RT-01): the task role previously had the AWS-managed
# `SecretsManagerReadWrite` policy attached, which grants read/write on every
# secret in the account. The application only ever needs to read its own DB
# credential secret at container startup, so this is replaced with an inline
# policy scoped to that single resource and to the read-only action.
resource "aws_iam_role_policy" "ecs-task-role-secrets-scoped" {
  name = "rds-creds-read-only"
  role = aws_iam_role.ecs-task-role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.rds_creds.arn]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs-instance-role-attachment-ssm" {
  role       = aws_iam_role.ecs-instance-role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}


data "aws_ami" "ecs_optimized_ami" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-2.0.202*-x86_64-ebs"]
  }
}


resource "aws_launch_template" "ecs_launch_template" {
  name_prefix   = "ecs-launch-template-"
  image_id      = data.aws_ami.ecs_optimized_ami.id
  instance_type = "t3.micro"

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs-instance-profile.name
  }

  vpc_security_group_ids = [aws_security_group.ecs_sg.id]
  user_data              = base64encode(data.template_file.user_data.rendered)
}

resource "aws_autoscaling_group" "ecs_asg" {
  name                = "ECS-lab-asg-${var.suffix}"
  vpc_zone_identifier = [aws_subnet.lab-subnet-public-1.id]
  desired_capacity    = 1
  min_size            = 0
  max_size            = 1

  launch_template {
    id      = aws_launch_template.ecs_launch_template.id
    version = "$Latest"
  }
}


resource "aws_ecs_cluster" "cluster" {
  name = "ecs-lab-cluster-${var.suffix}"

  tags = {
    name = "ecs-cluster-name"
  }
}

data "template_file" "user_data" {
  template = file("${path.module}/resources/ecs/user_data.tpl")
}

resource "aws_ecs_task_definition" "task_definition" {
  container_definitions    = data.template_file.task_definition_json.rendered
  family                   = "ECS-Lab-Task-definition"
  network_mode             = "bridge"
  memory                   = "512"
  cpu                      = "512"
  requires_compatibilities = ["EC2"]
  task_role_arn            = aws_iam_role.ecs-task-role.arn
  execution_role_arn       = aws_iam_role.ecs-task-role.arn

  # Remediation (RT-04 hardening): the previous definition set pid_mode="host"
  # and mounted host kernel module directories into the container, with the
  # SYS_PTRACE capability added in the container definition. None of this is
  # needed by a PHP/Apache app and it is a well-known container-escape vector
  # (ptrace against host processes visible via a shared PID namespace). Removed.
}

data "template_file" "task_definition_json" {
  template = file("${path.module}/resources/ecs/task_definition.json")
  depends_on = [
    null_resource.rds_endpoint,
    null_resource.build_and_push_image
  ]
}



resource "aws_ecs_service" "worker" {
  name                              = "ecs_service_worker"
  cluster                           = aws_ecs_cluster.cluster.id
  task_definition                   = aws_ecs_task_definition.task_definition.arn
  desired_count                     = 1
  health_check_grace_period_seconds = 2147483647

  load_balancer {
    target_group_arn = aws_lb_target_group.target_group.arn
    container_name   = "aws-goat-m2"
    container_port   = 80
  }
  depends_on = [aws_lb_listener.listener]
}

resource "aws_alb" "application_load_balancer" {
  name               = "aws-goat-m2-alb-${var.suffix}"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.lab-subnet-public-1.id, aws_subnet.lab-subnet-public-1b.id]
  security_groups    = [aws_security_group.load_balancer_security_group.id]

  tags = {
    Name = "aws-goat-m2-alb"
  }
}

resource "aws_lb_target_group" "target_group" {
  name        = "aws-goat-m2-tg-${var.suffix}"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.lab-vpc.id

  tags = {
    Name = "aws-goat-m2-tg"
  }
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_alb.application_load_balancer.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.id
  }
}


resource "aws_secretsmanager_secret" "rds_creds" {
  name                    = "RDS_CREDS_${var.suffix}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id = aws_secretsmanager_secret.rds_creds.id
  secret_string = jsonencode({
    username = "root"
    password = random_password.rds_master.result
  })
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/aws-goat-m2-${var.suffix}"
  retention_in_days = 14
}

# Remediation (RT-04): the running task previously pulled a public, unpatched
# image (public.ecr.aws/p3q0v3y2/aws-goat-m2). Editing the Dockerfile/PHP
# source alone would have no effect on what is actually deployed, so a
# private ECR repo is created and the patched image (SQLi fix, upload
# validation, authenticated document downloads, sudoers rule removed) is
# built and pushed from wherever `terraform apply` runs (this matches the
# existing GitHub Actions workflow, whose ubuntu-latest runner ships Docker).
resource "aws_ecr_repository" "app" {
  name                 = "aws-goat-m2-${var.suffix}"
  image_tag_mutability = "MUTABLE"

  provisioner "local-exec" {
    when        = destroy
    command     = "aws ecr batch-delete-image --repository-name ${self.name} --region us-east-1 --image-ids imageTag=latest || true"
    interpreter = ["/bin/bash", "-c"]
  }
}

resource "null_resource" "build_and_push_image" {
  triggers = {
    src_hash = sha1(join("", [for f in fileset("${path.module}/src/src", "**") : filesha1("${path.module}/src/src/${f}")]))
    dockerfile_hash = filesha1("${path.module}/src/Dockerfile")
  }

  provisioner "local-exec" {
    command     = <<EOF
set -euo pipefail
REGISTRY="${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
aws ecr get-login-password --region ${data.aws_region.current.name} | docker login --username AWS --password-stdin "$REGISTRY"
docker build -t "$REGISTRY/${aws_ecr_repository.app.name}:latest" ${path.module}/src
docker push "$REGISTRY/${aws_ecr_repository.app.name}:latest"
EOF
    interpreter = ["/bin/bash", "-c"]
  }

  depends_on = [aws_ecr_repository.app]
}

resource "null_resource" "rds_endpoint" {
  provisioner "local-exec" {
    command     = <<EOF
RDS_URL="${aws_db_instance.database-instance.endpoint}"
RDS_URL=$${RDS_URL::-5}
IMAGE_URI="${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${aws_ecr_repository.app.name}:latest"
sed -i "s,RDS_ENDPOINT_VALUE,$RDS_URL,g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,ECS_IMAGE_VALUE,$IMAGE_URI,g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,RDS_SECRET_ARN_VALUE,${aws_secretsmanager_secret.rds_creds.arn},g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,ECS_LOGGROUP_VALUE,${aws_cloudwatch_log_group.app.name},g" ${path.module}/resources/ecs/task_definition.json
EOF
    interpreter = ["/bin/bash", "-c"]
  }

  depends_on = [
    aws_db_instance.database-instance, null_resource.build_and_push_image, aws_secretsmanager_secret_version.secret_version
  ]
}

resource "null_resource" "cleanup" {
  provisioner "local-exec" {
    command     = <<EOF
RDS_URL="${aws_db_instance.database-instance.endpoint}"
RDS_URL=$${RDS_URL::-5}
IMAGE_URI="${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${aws_ecr_repository.app.name}:latest"
sed -i "s,$RDS_URL,RDS_ENDPOINT_VALUE,g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,$IMAGE_URI,ECS_IMAGE_VALUE,g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,${aws_secretsmanager_secret.rds_creds.arn},RDS_SECRET_ARN_VALUE,g" ${path.module}/resources/ecs/task_definition.json
sed -i "s,${aws_cloudwatch_log_group.app.name},ECS_LOGGROUP_VALUE,g" ${path.module}/resources/ecs/task_definition.json
EOF
    interpreter = ["/bin/bash", "-c"]
  }

  depends_on = [
    null_resource.rds_endpoint, aws_ecs_task_definition.task_definition
  ]
}


/* Creating a S3 Bucket for Terraform state file upload. */
resource "aws_s3_bucket" "bucket_tf_files" {
  bucket        = "do-not-delete-awsgoat-state-files-${data.aws_caller_identity.current.account_id}-${var.suffix}"
  force_destroy = true
  tags = {
    Name        = "Do not delete Bucket"
    Environment = "Dev"
  }
}

output "ad_Target_URL" {
  value = "${aws_alb.application_load_balancer.dns_name}:80/login.php"
}


# ---------------------------------------------------------------------------
# Cost guardrail: alert if the lab is left running / abused.
# A monthly account COST budget that emails when spend crosses the thresholds.
# Override the email/limit with -var or a tfvars file.
# ---------------------------------------------------------------------------
variable "budget_alert_email" {
  description = "Email address that receives AWSGoat budget alerts."
  type        = string
  default     = "hikari@toadsec.io"
}

variable "monthly_budget_limit_usd" {
  description = "Monthly cost budget for the AWSGoat lab, in USD."
  type        = string
  default     = "20"
}

resource "aws_budgets_budget" "awsgoat_module_2_monthly_cost" {
  name         = "awsgoat-module-2-monthly-cost-${var.suffix}"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
