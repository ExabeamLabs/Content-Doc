#### Parser Content
```Java
{
Name = cef-sentinelone-network-alert-1
  Product = SentinelOne
  DataType = "network-connection"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|ip|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """dstIp:({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """srcIp:({src_ip}[a-fA-F\d.:]{1,2000})""",
    """dstPort:({dest_port}\d{1,100})""",
    """srcPort:({src_port}\d{1,100})""",
  ]

cef-sentinelone-security-alert = {
    Vendor = SentinelOne
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}({host}\S+)""",
      """\seventType:(|({alert_type}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentId:(|({agent_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentIp:({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\sagentName:(|({dest_host}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sagentfileFullNameGroupId:(|({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}\w+))?)))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sprocessName:(|({process_name}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
      """\sid:(|({alert_id}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    
}
```