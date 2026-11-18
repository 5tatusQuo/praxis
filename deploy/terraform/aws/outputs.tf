output "dashboard_url" {
  description = "Point your DNS name at this load balancer."
  value       = "https://${aws_lb.praxis.dns_name}"
}

output "secret_arn" {
  description = "Secrets Manager secret holding the API token and the database URL."
  value       = aws_secretsmanager_secret.praxis.arn
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}
