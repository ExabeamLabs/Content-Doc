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
   """"+Alert Id"+:"+({alert_id}[^"]+)""",
   """"+Timestamp"+:"+({time}[^"]+)""",
   """"+Computer Name"+:"+({host}[^"]+)""",
   """"+Computer IP"+:"+({dest_ip}[A-Za-z0-9.:]+)""",
   """"+Intel Type"+:"+({alert_type}[^"]+)""",
   """"+Intel Name"+:"+({alert_name}[^"]+)""",
   """"properties"+:[^\]]+?fullpath"+:"+({process}({process_directory}[^"]+)\\+({process_name}[^"]+))""",
   """"properties"+:[^\]]+?md5"+:"+({md5}[^"]+)""",
   """"properties"+:[^\]]+?args"+:"+\\*"+({command_line}[^\]]+?)\s*"+,"+cwd""",
   """"properties"+:[^\]]+?"+user"+:"+((NT AUTHORITY|({domain}[^\\]+))\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
   """"os"+:"+({os}[^"]+)"""
 ]
 DupFields = [ "process_directory->directory", "process->path" ]
}
```