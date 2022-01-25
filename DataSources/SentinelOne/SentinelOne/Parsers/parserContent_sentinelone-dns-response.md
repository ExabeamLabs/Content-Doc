#### Parser Content
```Java
{
Name = sentinelone-dns-response
  DataType = "dns-response"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """dns {""","""results:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """\squery:\s{0,100}"{1,20}({query}[^"]{1,2000})""",
    """\squery:\s{0,100}"{1,20}({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """results:\s{0,100}"{1,20}({response}[^"]{1,2000})"""
  ]
}
```