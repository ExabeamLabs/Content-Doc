#### Parser Content
```Java
{
Name = palo-alto-cortex-xdr-alert
  Vendor = Palo Alto Networks
  Product = Cortex XDR
  Lms = Direct
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,alert,""" , """,true,""" ]
  Fields = [
  """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
  """"{1,20}\["{1,20}({src_ip}[A-Fa-f\d:.]{1,2000}).+?"{1,20}\]"{1,20},([^,]{0,2000},){8}({user_sid}[^,]{1,2000}),({domain}[^\\]{1,2000})\\(SYSTEM|({user}[^,]{1,2000}))""",
  """"{1,20}\["{1,20}(?:[A-Fa-f\d:.]{1,2000}).+?"{1,20}\]"{1,20},([^,]{0,2000},){17}({file_path}({file_parent}[^"][^,]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/]{0,2000}?(\.({file_ext}\w+))?)),""",
  """,alert,([^,]{0,2000},){8}({alert_severity}[^,]{1,2000})""",
  """,alert,([^,]{0,2000},){14}({alert_name}[^,]{1,2000}),({alert_type}[^,]{1,2000}),"{0,20}({additional_info}[^"]{1,2000})"{0,20},""",
  ]
  DupFields = [ "file_name->malware_file_name" ]
}
```