#### Parser Content
```Java
{
Name = forcepoint-network-connection-successful
  Product = Forcepoint NGFW
  DataType = "network-connection-successful"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Allowed|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s*({protocol}.+?)(\s\w+=)""",
    ]
}
```