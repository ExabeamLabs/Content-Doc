#### Parser Content
```Java
{
Name = sentinelone-dns-query
  DataType = "dns-query"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """ndns {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """\squery:\s{0,100}"{1,20}({query}[^"]{1,2000})""",
  ]
  DupFields = ["host->src_host"]
}
}
```