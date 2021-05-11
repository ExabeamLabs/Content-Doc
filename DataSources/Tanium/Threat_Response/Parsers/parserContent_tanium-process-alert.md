#### Parser Content
```Java
{
Name = tanium-process-alert
 Product = Threat Response
 Vendor = Tanium
 Lms = Direct
 DataType = "process-alert"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = [ """Intel Id""", """Intel Type""", """Intel Name""", """Intel Labels""", """recorder_unique_id""", """"type"""",""""process"""" ]
 Fields=[
   """"{1,20}Alert Id"{1,20}:"{1,20}({alert_id}[^"]+)""",
   """"{1,20}Timestamp"{1,20}:"{1,20}({time}[^"]+)""",
   """"{1,20}Computer Name"{1,20}:"{1,20}({host}[^".]+)""",
   """"{1,20}Computer IP"{1,20}:"{1,20}({dest_ip}[A-Za-z0-9.:]+)""",
   """"{1,20}Intel Type"{1,20}:"{1,20}({alert_type}[^"]+)""",
   """"{1,20}Intel Name"{1,20}:"{1,20}({alert_name}[^"]+)""",
   """"properties"{1,20}:[^\]]+?fullpath"{1,20}:"{1,20}({process}({process_directory}[^"]+)\\+({process_name}[^"]+))""",
   """"properties"{1,20}:[^\]]+?md5"{1,20}:"{1,20}({md5}[^"]+)""",
   """"properties"{1,20}:[^\]]+?args"{1,20}:"{1,20}\\*"{1,20}({command_line}[^\]]+?)\s{0,100}"{1,20}\,"{1,20}cwd""",
   """"user"{1,20}:"{1,20}(?:(?:NT AUTHORITY|({domain}[^\\"]+))\\+)?(?:SYSTEM|LOCAL SERVICE|({user}[^"]+))"{1,20}\}\,"{1,20}source"{1,20}:""",
   """"os"{1,20}:"{1,20}({os}[^"]+)"""
 ]
 DupFields = [ "process_directory->directory", "process->path" ]
}
```