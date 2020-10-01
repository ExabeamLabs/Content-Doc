#### Parser Content
```Java
{
Name = auth0-login-success
  DataType = "app-login"
  Conditions = [ """"type":"s"""", """"user_id"""", """"client_name"""", """"client_id""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}s)"""",
  ]
}
```