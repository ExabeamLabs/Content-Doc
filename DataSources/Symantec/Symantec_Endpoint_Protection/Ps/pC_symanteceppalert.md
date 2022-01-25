#### Parser Content
```Java
{
Name = symantec-epp-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Actual action:""",""",Requested action:""" ]
  Fields = [
         """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
         """exabeam_host=({host}\S+)""",
         """Computer name:\s{0,100}(?:0+|({host}[^,]{1,2000}))""",
         """Event time:\s{0,100}({time}[\d\- :]{1,2000})""",
         """({alert_type}Virus found)""",
         """IP Address:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
         """Risk name:\s{0,100}({alert_name}[^,]{1,2000})""",
         """\d\d:\d\d:\d\d,\s{0,100}({alert_severity}Minor|Info|Critical|Major|Security risk found|Virus found)""",
         """Sensitivity:\s({alert_severity}[^,]{1,2000})""",
         """Risk Level:\s{0,100}({alert_severity}[^,]{1,2000})""",
         """Occurrences:\s{0,100}\d{1,100

}
```