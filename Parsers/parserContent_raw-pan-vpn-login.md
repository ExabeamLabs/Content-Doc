#### Parser Content
```Java
{
Name = raw-pan-vpn-login
  DataType = "vpn-login"
  Conditions = [ """,GLOBALPROTECT,""", """,connected,""", """,success,"""]
  Fields = ${PaloAltoParserTemplates.raw-pan-vpn-event.Fields}[
    """,({app}GLOBALPROTECT),""",
    """({outcome}success|Success|SUCCESS)""",
  ]
}
```