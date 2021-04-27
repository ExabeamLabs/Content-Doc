#### Parser Content
```Java
{
Name = sentinelone-network-connection-1
  DataType = "network-connection"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """ntcpv4 {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}tcpv4)""",
  ]
}
```