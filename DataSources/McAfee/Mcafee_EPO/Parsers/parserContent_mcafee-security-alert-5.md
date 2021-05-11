#### Parser Content
```Java
{
Name = mcafee-security-alert-5
  Vendor = McAfee
  Product = Mcafee EPO
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """:epoEventEventDesc: 'STRING:""", """:epoEventThreatCategory: 'STRING:""", """:epoEventThreatActionTaken: 'STRING:""" ]
  Fields = [
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s{1,100}({host}[\w\-.]+)\s{1,100}\w+""",
    """:epoEventEventDesc:\s{0,100}'STRING:\s{0,100}\\?"({alert_name}[^"]+?)\\?"""",
    """:epoEventTargetIPV6:\s{0,100}'STRING:\s{0,100}\\?"({dest_ip}[A-Fa-f:\d.]+)""",
    """:epoEventTargetProcessName:\s{0,100}'STRING:\s{0,100}\\?"({process}(({directory}[^"]*?)\\)?({process_name}[^"\\]*?))\\?"""",
    """:epoEventTargetFileName:\s{0,100}'STRING:\s{0,100}\\?"(|({file_path}(|({file_parent}[^"]*?))[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\\?"""",
    """:epoEventTargetUserName:\s{0,100}'STRING:\s{0,100}\\?"(({domain}[^\\\s"']+)\\+)?(SYSTEM|({user}[^\\\s"']+))\\?"""",
    """:epoEventThreatCategory:\s{0,100}'STRING:\s{0,100}\\?"({alert_type}[^"]+?)\\?"""",
    """:epoEventThreatSeverity:\s{0,100}'STRING:\s{0,100}\\?"({alert_severity}[^"']+?)\\?"""",
    """:epoEventThreatActionTaken:\s{0,100}'STRING:\s{0,100}\\?"(None|({outcome}[^"']+?))\\?"""",
    """:epoEventOsType:\s{0,100}'STRING:\s{0,100}\\?"({os}[^"']+?)\\?""""
  ]
  DupFields = [ "alert_type->threat_category" ]
}
```