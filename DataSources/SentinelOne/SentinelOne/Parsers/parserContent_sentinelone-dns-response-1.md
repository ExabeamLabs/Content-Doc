#### Parser Content
```Java
{
Name = sentinelone-dns-response-1
  DataType = "dns-response"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """dns {""","""results:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """query:\s{0,100}\\?"{1,20}({query}[^"]+?)\.?\\?"""",
    """results:\s{0,100}\\?"{1,20}({response}[^"]+?)\\?""""
  ]
}
```