#### Parser Content
```Java
{
Name = cef-carbonblack-network-connection-successful-2
  DataType = "network-connection"
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """act=connect""" ]
  Fields = ${CarbonBlackParserTemplates.cef-carbonblack-events-1.Fields} [
    """({outcome}successful)""",
  ]
}
```