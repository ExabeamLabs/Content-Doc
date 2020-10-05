#### Parser Content
```Java
{
Name = auth0-login-failed
  DataType = "failed-logon"
  Conditions = [ """"type":"fp"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}fp)"""",
    """consoleOut"+:"+({failure_reason}[^"]+)"+""",
  ]
}
```