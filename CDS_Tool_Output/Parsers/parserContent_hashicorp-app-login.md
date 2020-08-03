#### Parser Content
```Java
{
Name = hashicorp-app-login
  DataType = "app-login"
  Conditions = [ """"type":"request"""", """"auth":{""", """"token_type"""", """"ttam_service":"vault"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} []
}
```