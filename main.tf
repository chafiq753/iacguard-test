# =============================================================================
#  Terraform DEMO — volontairement truffé de failles, pour tester iac-guard.
#  Ne JAMAIS appliquer ce code (`terraform apply`) : ce n'est pas fait pour
#  tourner, juste pour être scanné.
#
#  SECURE SECRETS HANDLING (Section 12-bis):
#  Passer le token GitHub via variable d'environnement SANS le commiter :
#    export TF_VAR_github_deploy_token="ghp_your_actual_token_here"
#    terraform plan
#
#  Ou via fichier terraform.tfvars.local (ajouté à .gitignore) :
#    github_deploy_token = "ghp_your_actual_token_here"
# =============================================================================

provider "aws" {
  region = "us-east-1"

  # 1) SECRET EN DUR -> Gitleaks le détecte (aws-access-token, critique) et
  #    Checkov aussi (CKV_AWS_41). Clé FACTICE inventée pour la démo : elle
  #    n'existe pas chez AWS et ne donne accès à rien.
  #    Ne pas remettre les clés « ...EXAMPLE » de la doc AWS : Gitleaks les
  #    ignore volontairement, la démo ne montrerait aucun secret.
  access_key = "AKIAZ7IACGUARDDEMO42"
  secret_key = "FAKE-iacguard-demo-secret-not-a-real-key"
}

# 2) Bucket S3 public en lecture -> CKV_AWS_20
resource "aws_s3_bucket" "public_assets" {
  bucket = "iacguard-demo-public-assets"
  acl    = "public-read"
}

# 3) Bucket S3 sans versioning -> CKV_AWS_21 (perte de données possible)
resource "aws_s3_bucket" "backups" {
  bucket = "iacguard-demo-backups"
}

# 4) Security group : SSH ouvert au monde entier -> CKV_AWS_24
resource "aws_security_group" "bastion" {
  name = "bastion-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 5) Security group : RDP ouvert au monde entier -> CKV_AWS_25
resource "aws_security_group" "windows" {
  name = "windows-sg"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 6) Volume EBS non chiffré -> CKV_AWS_3
resource "aws_ebs_volume" "cache" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

# 7) Base de données non chiffrée + mot de passe en dur -> CKV_AWS_16 + secret
resource "aws_db_instance" "analytics" {
  identifier         = "analytics"
  engine             = "postgres"
  instance_class     = "db.t3.micro"
  allocated_storage  = 20
  username           = "admin"
  password           = "SuperSecret123!"
  storage_encrypted  = false
  publicly_accessible = true # 8) base accessible publiquement -> CKV_AWS_17
}

# 9) IAM policy bien trop permissive -> CKV_AWS_1 / CKV_AWS_62 (Action: "*")
resource "aws_iam_policy" "god_mode" {
  name = "god-mode-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# 12-bis) Données AWS et Variables pour gestion sécurisée des secrets
data "aws_region" "current" {}

variable "github_deploy_token" {
  description = "GitHub deploy token - à passer via environment variable ou terraform.tfvars (marqué sensible)"
  type        = string
  sensitive   = true
  default     = "" # Ne JAMAIS mettre de valeur par défaut en production
}

# Secrets Manager pour stocker le token de déploiement
resource "aws_secretsmanager_secret" "github_token" {
  name                    = "github-deploy-token"
  recovery_window_in_days = 7
  description             = "GitHub deployment token stored securely in AWS Secrets Manager"
}

resource "aws_secretsmanager_secret_version" "github_token" {
  secret_id     = aws_secretsmanager_secret.github_token.id
  secret_string = var.github_deploy_token
}

# IAM role pour EC2 - accès au Secrets Manager
resource "aws_iam_role" "ec2_secrets_role" {
  name = "ec2-secrets-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_secrets_policy" {
  name   = "ec2-secrets-access-policy"
  role   = aws_iam_role.ec2_secrets_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.github_token.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_secrets_profile" {
  name = "ec2-secrets-profile"
  role = aws_iam_role.ec2_secrets_role.name
}

# 10) Logging CloudTrail désactivé -> CKV_AWS_67 (pas de piste d'audit)
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.backups.id
  enable_logging                = false
  enable_log_file_validation    = false
}

# 11) Instance EC2 avec IP publique + sans monitoring détaillé
resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  monitoring                  = false

  # 12) FIXED: User-data récupère le token depuis AWS Secrets Manager (sécurisé)
  user_data = base64encode(<<-EOF
    #!/bin/bash
    DEPLOY_TOKEN=$(aws secretsmanager get-secret-value --secret-id github-deploy-token --query SecretString --output text --region ${data.aws_region.current.name})
    export DEPLOY_TOKEN="$DEPLOY_TOKEN"
  EOF
  )

  iam_instance_profile = aws_iam_instance_profile.ec2_secrets_profile.name

  depends_on = [aws_secretsmanager_secret_version.github_token]
}
