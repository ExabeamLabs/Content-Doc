#### Parser Content
```Java
{
Name = hashicorp-app-login-2
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  DataType = "app-login"
  Conditions = [ """"type":"""", """"auth":{""", """"operation":"""", """"token_type"""", """"source":"/var/log/vault.d/audit.log"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} [
    """"host"{1,20}:\{"{1,20}name"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"@timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)"""
  ]
}
```