#### Parser Content
```Java
{
Name = auth0-password-breached
  DataType = "security-alert"
  Conditions = [ """"type":"pwd_leak"""", """"user_id"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({alert_name}pwd_leak)"""",
  ]
}
```