#### Parser Content
```Java
{
Name = forcepoint-network-connection-failed
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """|FORCEPOINT|""", """|Connection_Discarded|""" ]
  Fields = ${ForcepointParserTemplates.forcepoint-template.Fields} [
    """proto=\s*({protocol}.+?)(\s\w+=)""",
    ]
}
```