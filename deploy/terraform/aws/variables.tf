variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "praxis"
}

variable "vpc_id" {
  description = "VPC to deploy into."
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets for the database and the services (at least two availability zones)."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Subnets for the load balancer."
  type        = list(string)
}

variable "allowed_cidrs" {
  description = "Networks allowed to reach the dashboard. Keep this to your own ranges."
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate for HTTPS on the load balancer."
  type        = string
}

variable "image_registry" {
  description = "Registry holding the praxis-api and praxis-web images."
  type        = string
  default     = "ghcr.io/5tatusquo"
}

variable "image_tag" {
  description = "Image tag to run."
  type        = string
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
