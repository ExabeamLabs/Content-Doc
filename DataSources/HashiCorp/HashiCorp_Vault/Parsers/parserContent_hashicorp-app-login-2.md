#### Parser Content
```Java
{
Name = hashicorp-app-login-2
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  DataType = "app-login"
  Conditions = [ """"type":"""", """"auth":{""", """"operation":"""", """"token_type"""", """"source":"/var/log/vault.d/audit.log"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} [
    """"host"+:\{"+name"+:"+({host}[^"]+)""",
    """"@timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)"""
  ]
}
```