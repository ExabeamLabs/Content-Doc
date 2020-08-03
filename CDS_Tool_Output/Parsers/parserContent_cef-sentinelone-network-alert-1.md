#### Parser Content
```Java
{
Name = cef-sentinelone-network-alert-1
  Product = SentinelOne
  DataType = "network-connection"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|ip|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """dstIp:({dest_ip}[a-fA-F\d.:]+)""",
    """srcIp:({src_ip}[a-fA-F\d.:]+)""",
    """dstPort:({dest_port}\d+)""",
    """srcPort:({src_port}\d+)""",
  ]
}
```