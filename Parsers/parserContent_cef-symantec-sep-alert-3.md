#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-3
  Conditions = [ """CEF:""", """|Symantec|""", """|sep_proxy_sonar_event|""" ]
  Fields = ${SymantecParserTemplates.cef-symantec-sep-alert.Fields}[
    """({host}[\w.\-]+)\s+sep_proxy_sonar_event:""",
  ]
}
```