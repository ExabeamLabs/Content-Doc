#### Parser Content
```Java
{
Name = cef-sentinelone-network-alert
  Product = SentinelOne
  DataType = "dns-query"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|dns|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\sdnsRequest:({query}[^\s]+)""",
    """\sdnsRequest:({query}[^\s]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""
    """\sdnsResponse:(|({response}.+?))(\s+\w+:|\s*$)""",
  ]
}
```