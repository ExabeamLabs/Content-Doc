#### Parser Content
```Java
{
Name = raw-pan-vpn-app-activity
  DataType = "app-activity"
  Conditions = [ """,GLOBALPROTECT,"""]
  Fields = ${PaloAltoParserTemplates.raw-pan-vpn-event.Fields}[
    """,({app}GLOBALPROTECT),""",
  ]
}
```