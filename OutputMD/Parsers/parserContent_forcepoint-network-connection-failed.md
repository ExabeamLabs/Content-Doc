#### Parser Content
```Java
{
Name = forcepoint-network-connection-failed
  Product = Forcepoint NGFW
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Discarded|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s*({protocol}.+?)(\s\w+=)""",
    ]
}
```