#### Parser Content
```Java
{
Name = vectra-activity-1
  Product = Vectra
  Vendor = Vectra
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""reason""","""action""","""src_name"""]
  Fields =[
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """({app}vectra)""",
    """"*dvchost"*:\s*"+({host}[^"]+)""",
    """"*src_name"*:\s*"+({src_host}[^"]+)""",
    """"*dest_name"*:\s*"+({dest_host}[^"]+)""",
    """"*src_ip"*:\s*"+({src_ip}[^"]+)""",
    """"*action"*:\s*"+({activity}[^"]+)""",
    """"*dest_ip"*:\s*"+({dest_ip}[^"]+)""",
    """"*reason"*:\s*"+({result}[^"]+)"""
  ]
 }

${SentinelOneParserTemplates.sentinelone-activity}{
  Name = sentinelone-dns-query
  DataType = "dns-query"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """ndns""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}ndns)""",
    """\squery:\s*"+({query}[^"]+)""",
  ]
}
```