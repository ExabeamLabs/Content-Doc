#### Parser Content
```Java
{
Name = forcepoint-network-connection-successful
  DataType = "network-connection-successful"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Allowed|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s*({protocol}.+?)(\s\w+=)""",
    ]
}
```