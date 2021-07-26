#### Parser Content
```Java
{
Name = forcepoint-network-connection-successful
  Product = Forcepoint NGFW
  DataType = "network-connection-successful"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Allowed|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s{0,100}({protocol}.+?)(\s\w+=)""",
    ]
}
```