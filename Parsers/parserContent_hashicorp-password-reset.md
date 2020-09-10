#### Parser Content
```Java
{
Name = hashicorp-password-reset
  DataType = "account-password-reset"
  Conditions = [ """"type":"request"""", """"auth":{""", """"operation":"create"""", """"token_type"""", """"ttam_service":"vault"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} []
}
```