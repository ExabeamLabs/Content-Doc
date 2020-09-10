#### Parser Content
```Java
{
Name = cef-carbonblack-file-read-2
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """act=create""", """was accessed by""" ]
  Fields = ${CarbonBlackParserTemplates.cef-carbonblack-events-1.Fields} [
    """({accesses}accessed)""",
  ]
}
```