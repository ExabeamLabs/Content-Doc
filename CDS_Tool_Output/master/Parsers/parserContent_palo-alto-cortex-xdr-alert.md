#### Parser Content
```Java
{
Name = palo-alto-cortex-xdr-alert
  Vendor = PA Cortex
  Product = Cortex XDR
  Lms = Direct
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,alert,""" , """,true,""" ]
  Fields = [
  """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
  """"+\["+({src_ip}[A-Fa-f\d:.]+).+?"+\]"+,([^,]*,){8}({user_sid}[^,]+),({domain}[^\\]+)\\(SYSTEM|({user}[^,]+))""",
  """"+\["+(?:[A-Fa-f\d:.]+).+?"+\]"+,([^,]*,){17}({file_path}({file_parent}[^"][^,]*?[\\\/]+)?({file_name}[^\\\/]*?(\.({file_ext}\w+))?)),""",
  """,alert,([^,]*,){8}({alert_severity}[^,]+)""",
  """,alert,([^,]*,){14}({alert_name}[^,]+),({alert_type}[^,]+),"*({additional_info}[^"]+)"*,""",
  ]
  DupFields = [ "file_name->malware_file_name" ]
}
```