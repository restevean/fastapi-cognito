output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.main.arn
}

output "user_pool_client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.main.id
}

output "aws_region" {
  description = "AWS Region"
  value       = var.aws_region
}

output "cognito_issuer" {
  description = "Cognito token issuer URL (for JWT validation)"
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}

output "jwks_uri" {
  description = "JWKS URI for JWT validation"
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.main.id}/.well-known/jwks.json"
}

output "env_file_content" {
  description = "Content for .env file"
  value       = <<-EOT
    COGNITO_USER_POOL_ID=${aws_cognito_user_pool.main.id}
    COGNITO_CLIENT_ID=${aws_cognito_user_pool_client.main.id}
    AWS_REGION=${var.aws_region}
  EOT
}
