#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-2
  Conditions = [ """CEF:""", """|Symantec|""", """|sep_proxy_insight_event|""" ]
  Fields = ${SymantecParserTemplates.cef-symantec-sep-alert.Fields}[
    """({host}[\w.\-]+)\s+sep_proxy_insight_event:""",
  ]
}
```