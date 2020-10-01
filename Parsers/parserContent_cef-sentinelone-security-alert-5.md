#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-5
  Product = SentinelOne
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|url|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\snetworkUrl:(|({malware_url}.+?))(\s+\w+:|\s*$)""",
    """\snetworkMethod:(|({method}.+?))(\s+\w+:|\s*$)""",
    """http.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""

  ]
}
```