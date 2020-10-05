#### Parser Content
```Java
{
Name = auth0-login-failed-1
  DataType = "failed-logon"
  Conditions = [ """"type":"f"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}f)"""",
    """message"+:"+({failure_reason}[^"]+)"+,""",
  ]
}
```