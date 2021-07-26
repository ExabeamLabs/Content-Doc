#### Parser Content
```Java
{
Name = forcepoint-network-connection-failed
  Product = Forcepoint NGFW
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Discarded|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s{0,100}({protocol}.+?)(\s\w+=)""",
    ]
}
```