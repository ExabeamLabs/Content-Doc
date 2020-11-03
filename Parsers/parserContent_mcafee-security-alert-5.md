#### Parser Content
```Java
{
Name = mcafee-security-alert-5
  Vendor = Mcafee
  Product = Mcafee EPO
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """:epoEventEventDesc: 'STRING:""", """:epoEventThreatCategory: 'STRING:""", """:epoEventThreatActionTaken: 'STRING:""" ]
  Fields = [
    """\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s+({host}[\w\-.]+)\s+\w+""",
    """:epoEventEventDesc:\s*'STRING:\s*\\?"({alert_name}[^"]+?)\\?"""",
    """:epoEventTargetIPV6:\s*'STRING:\s*\\?"({dest_ip}[A-Fa-f:\d.]+)""",
    """:epoEventTargetProcessName:\s*'STRING:\s*\\?"({process}(({directory}[^"]*?)\\)?({process_name}[^"\\]*?))\\?"""",
    """:epoEventTargetFileName:\s*'STRING:\s*\\?"(|({file_path}(|({file_parent}[^"]*?))[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\\?"""",
    """:epoEventTargetUserName:\s*'STRING:\s*\\?"(({domain}[^\\\s"']+)\\+)?(SYSTEM|({user}[^\\\s"']+))\\?"""",
    """:epoEventThreatCategory:\s*'STRING:\s*\\?"({alert_type}[^"]+?)\\?"""",
    """:epoEventThreatSeverity:\s*'STRING:\s*\\?"({alert_severity}[^"']+?)\\?"""",
    """:epoEventThreatActionTaken:\s*'STRING:\s*\\?"(None|({outcome}[^"']+?))\\?"""",
    """:epoEventOsType:\s*'STRING:\s*\\?"({os}[^"']+?)\\?""""
  ]
  DupFields = [ "alert_type->threat_category" ]
}
```