#### Parser Content
```Java
{
Name = json-windows-auth
  DataType = "authentication-successful"
  Conditions = [ """"service":"sso"""" , """"authentication":{""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"status":"({outcome}[^"]+)""",
    """"key":"({reason}[^"]+)""",
    """"environment":"({realm}[^"]+)""",
    """"host":"({host}[^"]+)","@version"""",
  ]
}
```