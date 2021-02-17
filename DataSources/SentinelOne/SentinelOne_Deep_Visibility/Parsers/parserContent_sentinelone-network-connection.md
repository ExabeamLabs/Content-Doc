#### Parser Content
```Java
{
Name = sentinelone-network-connection
  DataType = "network-connection"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """ntcpv4 {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}tcpv4)""",
  ]
}
```