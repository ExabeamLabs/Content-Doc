#### Parser Content
```Java
{
Name = json-4648-1
  DataType = "windows-account-switch"
  Conditions = [ """"event-id":4648""", """"message":"A logon was attempted using explicit credentials""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"service":"({dest_service}[^"]+)""",
    """"user":\{[^\}]*?"uid":"({account}[^"]+)""",
    """"domain":"({account_domain}[^"]+)""",
    """"ad":\{[^\}]*?"subject-user-name":"({user}[^"]+)""",
    """"ad":\{[^\}]*?"subject-domain-name":"({domain}[^"]+)""",
    """"target-server-name":"({dest_service}[^"]+)""",
  ]
}
```