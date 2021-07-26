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
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\S*\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\w+""",
    """:epoEventEventDesc:\s{0,100}'STRING:\s{0,100}\\?"({alert_name}[^"]{1,2000}?)\\?"""",
    """:epoEventTargetIPV6:\s{0,100}'STRING:\s{0,100}\\?"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """:epoEventTargetProcessName:\s{0,100}'STRING:\s{0,100}\\?"({process}(({directory}[^"]{0,2000}?)\\)?({process_name}[^"\\]{0,2000}?))\\?"""",
    """:epoEventTargetFileName:\s{0,100}'STRING:\s{0,100}\\?"(|({file_path}(|({file_parent}[^"]{0,2000}?))[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)))\\?"""",
    """:epoEventTargetUserName:\s{0,100}'STRING:\s{0,100}\\?"(({domain}[^\\\s"']{1,2000})\\+)?(SYSTEM|({user}[^\\\s"']{1,2000}))\\?"""",
    """:epoEventThreatCategory:\s{0,100}'STRING:\s{0,100}\\?"({alert_type}[^"]{1,2000}?)\\?"""",
    """:epoEventThreatSeverity:\s{0,100}'STRING:\s{0,100}\\?"({alert_severity}[^"']{1,2000}?)\\?"""",
    """:epoEventThreatActionTaken:\s{0,100}'STRING:\s{0,100}\\?"(None|({outcome}[^"']{1,2000}?))\\?"""",
    """:epoEventOsType:\s{0,100}'STRING:\s{0,100}\\?"({os}[^"']{1,2000}?)\\?""""
  ]
  DupFields = [ "alert_type->threat_category" ]
}
```