#### Parser Content
```Java
{
Name = json-4625-1
  DataType = "windows-failed-logon"
  Conditions = [ """"event-id":4625""", """"message":"An account failed to log on""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"auth-package":"({auth_package}[^"]+)""",
    """"workstation-name":"({src_host_windows}[^"]+)""",
    """"ad":\{[^\}]*?"status":"({result_code}[^"]+)""",
  ]
}
```