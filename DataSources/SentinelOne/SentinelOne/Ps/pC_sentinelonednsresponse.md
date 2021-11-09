#### Parser Content
```Java
{
Name = sentinelone-dns-response
  DataType = "dns-response"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """dns {""","""results:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """\squery:\s{0,100}"{1,20}({query}[^"]{1,2000})""",
    """results:\s{0,100}"{1,20}({response}[^"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
}
```