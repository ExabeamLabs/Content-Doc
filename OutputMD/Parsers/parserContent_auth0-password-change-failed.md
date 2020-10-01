#### Parser Content
```Java
{
Name = auth0-password-change-failed
  DataType = "password-change"  
  Conditions = [ """"type":"fcp"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}fcp)"""",
  ]
  DupFields = [ "user->target_user" ]
}
```