resource "aws_cognito_user_pool" "main" {
  name = "${var.project_name}-${var.environment}"

  # Solo el administrador puede crear usuarios
  admin_create_user_config {
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "Tu cuenta ha sido creada"
      email_message = "Tu usuario es {username} y tu contraseña temporal es {####}"
      sms_message   = "Tu usuario es {username} y tu contraseña temporal es {####}"
    }
  }

  # Email como username
  username_attributes = ["email"]

  # Configuración de verificación
  auto_verified_attributes = ["email"]

  # Política de contraseñas
  password_policy {
    minimum_length                   = var.password_minimum_length
    require_lowercase                = var.password_require_lowercase
    require_uppercase                = var.password_require_uppercase
    require_numbers                  = var.password_require_numbers
    require_symbols                  = var.password_require_symbols
    temporary_password_validity_days = 7
  }

  # Atributos del usuario
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Configuración de recuperación de cuenta
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # MFA deshabilitado para simplificar
  mfa_configuration = "OFF"

  # Configuración de email (usando Cognito default)
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # Política de usuarios
  user_pool_add_ons {
    advanced_security_mode = "OFF"
  }
}

resource "aws_cognito_user_pool_client" "main" {
  name         = "${var.project_name}-client"
  user_pool_id = aws_cognito_user_pool.main.id

  # Sin client secret (para uso desde frontend JavaScript)
  generate_secret = false

  # Flujos de autenticación permitidos
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  # Configuración de tokens
  access_token_validity  = 1  # 1 hora
  id_token_validity      = 1  # 1 hora
  refresh_token_validity = 30 # 30 días

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Atributos que el cliente puede leer/escribir
  read_attributes  = ["email", "email_verified"]
  write_attributes = ["email"]

  # Prevenir errores de usuario
  prevent_user_existence_errors = "ENABLED"

  # Configuración de callback (no usamos hosted UI, pero es requerido)
  supported_identity_providers = ["COGNITO"]
}
