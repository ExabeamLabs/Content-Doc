#### Parser Content
```Java
{
Name = cef-sentinelone-network-alert-1
  DataType = "network-connection"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|ip|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """dstIp:({dest_ip}[a-fA-F\d.:]+)""",
    """srcIp:({src_ip}[a-fA-F\d.:]+)""",
    """dstPort:({dest_port}\d+)""",
    """srcPort:({src_port}\d+)""",
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