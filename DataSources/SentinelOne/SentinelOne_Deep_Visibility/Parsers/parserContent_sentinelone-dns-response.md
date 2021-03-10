#### Parser Content
```Java
{
Name = sentinelone-dns-response
  DataType = "dns-response"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """dns""","""results:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """\squery:\s*"+({query}[^"]+)""",
  ]
}
```