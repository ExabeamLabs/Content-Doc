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
    """\sdnsResponse:(|({response}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
  ]
}
cef-sentinelone-security-alert = {
    Vendor = SentinelOne
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}({host}\S+)""",
      """\seventType:(|({alert_type}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentId:(|({agent_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentIp:({dest_ip}[a-fA-F\d.:]+)""",
      """\sagentName:(|({dest_host}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentfileFullNameGroupId:(|({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}\w+))?)))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sprocessName:(|({process_name}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sid:(|({alert_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    ]

```