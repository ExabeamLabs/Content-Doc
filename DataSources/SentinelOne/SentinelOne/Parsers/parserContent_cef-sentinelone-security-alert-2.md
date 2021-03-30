#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-2
  Product = SentinelOne
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|process|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\suser:(|(({domain}[^\\\/]+)[\\\/]+)?(SYSTEM|({user}[^\\\/"]+?)))(\s+\w+:|\s*$)""",
    """\sprocessCmd:"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+?))\s*"""",
    """\ssha256:(|({sha256_sum}.+?))(\s+\w+:|\s*$)""",
  ]
}
cef-sentinelone-security-alert = {
    Vendor = SentinelOne
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s+({host}\S+)""",
      """\seventType:(|({alert_type}.+?))(\s+\w+:|\s*$)""",
      """\sagentId:(|({agent_id}.+?))(\s+\w+:|\s*$)""",
      """\sagentIp:({dest_ip}[a-fA-F\d.:]+)""",
      """\sagentName:(|({dest_host}.+?))(\s+\w+:|\s*$)""",
      """\sagentfileFullNameGroupId:(|({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}\w+))?)))(\s+\w+:|\s*$)""",
      """\sprocessName:(|({process_name}.+?))(\s+\w+:|\s*$)""",
      """\sid:(|({alert_id}.+?))(\s+\w+:|\s*$)""",
    ]

```