#### Parser Content
```Java
{
Name = cef-carbonblack-file-write-4
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """act=run""", """attempted to write""" ]
  Fields = ${CarbonBlackParserTemplates.cef-carbonblack-events-1.Fields} [
    """({accesses}write)""",
  ]
}
```