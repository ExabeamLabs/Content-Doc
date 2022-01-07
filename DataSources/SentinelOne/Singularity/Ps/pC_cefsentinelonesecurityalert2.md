#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-2
  Product = Singularity 
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|process|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\suser:(|(({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?(SYSTEM|({user}[^\\\/"]{1,2000}?)))(\s{1,100}\w+:|\s{0,100}$)""",
    """\sprocessCmd:"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}?))\s{0,100}"""",
    """\ssha256:(|({sha256_sum}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    """parentProcessName:({parent_process_name}[^:"]{1,2000}?)\s{1,100}\w+:""",
  ]
  DupFields = ["directory->process_directory"]

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