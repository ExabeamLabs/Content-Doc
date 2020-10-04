#### Parser Content
```Java
{
Name = tanium-process-alert
 Product= Threat Response
 Vendor= Tanium
 Lms= Direct
 DataType="process-alert"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions=["""Intel Id""", """Intel Type""", """Intel Name""", """Intel Labels""", """recorder_unique_id""", """"type"""",""""process"""" ]
 Fields=[
   """"+Alert Id"+:"+({alert_id}[^"]+)""",
   """"+Timestamp"+:"+({time}[^"]+)""",
   """"+Computer Name"+:"+({host}[^"]+)""",
   """"+Computer IP"+:"+({dest_ip}[A-Za-z0-9.:]+)""",
   """"+Intel Type"+:"+({alert_type}[^"]+)""",
   """"+Intel Name"+:"+({alert_name}[^"]+)""",
   """"+properties"+:.+?fullpath"+:"+({process}({process_directory}[^"]+)\\+({process_name}[^"]+))""",
   """"properties".+?md5"+:"+({md5}[^"]+)""",
   """properties"+.+?args"+:"+\\*"+({command_line}.+?)\s*"+,"+cwd""",
   """"hash".+?"+user"+:"+((NT AUTHORITY|({domain}[^\\]+))\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
   
 ]
}
{
  Name = prowatch-badge-access-3
  Vendor = Honeywell
  Product = Honeywell Pro-Watch
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "MM/dd/yyyy hh:mm:ss"
  Conditions = [ """prowatch:exabeam""","""ExaBeamTransaction""" ]
  Fields = [
	"""exabeam_host=({host}[^\s]+)""",
      """({employee_id}\w*)\|({first_name}[^|]*)\|({last_name}[^|]*)\|(\s*|({location_building}[^|]*))\|({location_city}[^|]*)\|(\s*|({location_state}[^|]*))\|({department}[^|]*)\|({badge_id}[^|]*)\|({location_door}.*?)\s*\|({time}\d\d\/\d\d\/\d{4} \d\d:\d\d:\d\d)\|({outcome}[^"]*)"""
  ]
}
```