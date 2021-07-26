#### Parser Content
```Java
{
Name = cef-carbonblack-network-connection-failed-1
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """act=connect""", """The operation failed""" ]
  Fields = ${CarbonBlackParserTemplates.cef-carbonblack-events-1.Fields} [
    """({outcome}failed)""",
  ]
}
```