provider "aws" {
  region = "ap-south-1"
}

# --------------------------
# VPC and Networking
# --------------------------
resource "aws_vpc" "pruthviraj_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pruthviraj-vpc"
  }
}

resource "aws_subnet" "pruthviraj_subnet" {
  count                   = 2
  vpc_id                  = aws_vpc.pruthviraj_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.pruthviraj_vpc.cidr_block, 8, count.index)
  availability_zone       = element(["ap-south-1a", "ap-south-1b"], count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "pruthviraj-subnet-${count.index}"
  }
}

resource "aws_internet_gateway" "pruthviraj_igw" {
  vpc_id = aws_vpc.pruthviraj_vpc.id
}

resource "aws_route_table" "pruthviraj_route_table" {
  vpc_id = aws_vpc.pruthviraj_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.pruthviraj_igw.id
  }
}

resource "aws_route_table_association" "pruthviraj_association" {
  count          = 2
  subnet_id      = aws_subnet.pruthviraj_subnet[count.index].id
  route_table_id = aws_route_table.pruthviraj_route_table.id
}

# --------------------------
# Security Groups
# --------------------------
resource "aws_security_group" "pruthviraj_cluster_sg" {
  vpc_id = aws_vpc.pruthviraj_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "pruthviraj-cluster-sg"
  }
}

resource "aws_security_group" "pruthviraj_node_sg" {
  vpc_id = aws_vpc.pruthviraj_vpc.id

  ingress {
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
    Name = "pruthviraj-node-sg"
  }
}

# --------------------------
# IAM Roles for EKS
# --------------------------
resource "aws_iam_role" "pruthviraj_cluster_role" {
  name = "pruthviraj-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "pruthviraj_cluster_role_policy" {
  role       = aws_iam_role.pruthviraj_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "pruthviraj_node_group_role" {
  name = "pruthviraj-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "pruthviraj_node_group_role_policy" {
  role       = aws_iam_role.pruthviraj_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "pruthviraj_node_group_cni_policy" {
  role       = aws_iam_role.pruthviraj_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "pruthviraj_node_group_registry_policy" {
  role       = aws_iam_role.pruthviraj_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "pruthviraj_node_group_ebs_policy" {
  role       = aws_iam_role.pruthviraj_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# --------------------------
# EKS Cluster
# --------------------------
resource "aws_eks_cluster" "pruthviraj" {
  name     = "pruthviraj-cluster"
  role_arn = aws_iam_role.pruthviraj_cluster_role.arn

  vpc_config {
    subnet_ids         = aws_subnet.pruthviraj_subnet[*].id
    security_group_ids = [aws_security_group.pruthviraj_cluster_sg.id]
  }

  depends_on = [aws_iam_role_policy_attachment.pruthviraj_cluster_role_policy]
}

# --------------------------
# OIDC Provider (for IRSA)
# --------------------------
data "aws_eks_cluster" "this" {
  name = aws_eks_cluster.pruthviraj.name
}

data "tls_certificate" "eks" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

# --------------------------
# IRSA Role for EBS CSI
# --------------------------
resource "aws_iam_role" "ebs_csi_irsa" {
  name = "AmazonEKS_EBS_CSI_DriverRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Federated = aws_iam_openid_connect_provider.this.arn
      },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "${replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_policy" {
  role       = aws_iam_role.ebs_csi_irsa.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# --------------------------
# EKS Addon (EBS CSI)
# --------------------------
resource "aws_eks_addon" "ebs_csi_driver" {
  cluster_name             = aws_eks_cluster.pruthviraj.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi_irsa.arn

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_iam_role_policy_attachment.ebs_csi_policy]
}

# --------------------------
# EKS Node Group
# --------------------------
resource "aws_eks_node_group" "pruthviraj" {
  cluster_name    = aws_eks_cluster.pruthviraj.name
  node_group_name = "pruthviraj-node-group"
  node_role_arn   = aws_iam_role.pruthviraj_node_group_role.arn
  subnet_ids      = aws_subnet.pruthviraj_subnet[*].id

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  remote_access {
    ec2_ssh_key               = var.ssh_key_name
    source_security_group_ids = [aws_security_group.pruthviraj_node_sg.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.pruthviraj_node_group_role_policy,
    aws_iam_role_policy_attachment.pruthviraj_node_group_cni_policy,
    aws_iam_role_policy_attachment.pruthviraj_node_group_registry_policy,
    aws_iam_role_policy_attachment.pruthviraj_node_group_ebs_policy
  ]
}
