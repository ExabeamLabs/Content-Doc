#### Parser Content
```Java
{
Name = zoom-meeting-ended
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """"event":"meeting.ended"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """"end_time"\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)"""",
    """"event"\s*:\s*"meeting.({activity}ended)"""",
    """"id"\s*:\s*"({meeting_number}\d+)""",
    """"topic"\s*:\s*"({meeting_topic}[^"]+)"""",
    """"type"\s*:\s*({meeting_type}\d)""",
    """"duration"\s*:\s*({meeting_duration}\d+)""",
    """"timezone"\s*:\s*"({meeting_timezone}[^"]+)"""",
    """"host_id"\s*:\s*"({meeting_host_id}[^"]+)""""
  ]
}

{
 Name = sail-file-operation
 Vendor = Sailpoint
 Product = SecurityIQ
 Lms= Direct
 DataType="file-read"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
 Conditions=["""action type\""", """object name\""", """samaccountname\""", """creation_timestamp\""", """application type\""" ]
 Fields=[
   """creation_timestamp\\"+:\\"+({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
   """message"+:\s*"+[^\s]+\s+({host}[^\s]+)""",
   """"+samaccountname\\"+:\\"+({user}[^\\"]+)""",
   """"+userprincipalname\\"+:\\"+({user_email}[^\\"]+)""",
   """"+object name\\"+:\\"+({file_name}[^\\"]+)""",
   """"+file extension\\"+:\\"+({file_extension}[^\\"]+)""",
   """"+ip address\\"+:\\"+({src_ip}[^\\"]+)""",
   """"+domain\\"+:\\"+({domain}[^\\"]+)""",
   """"+application type\\"+:\\"+({app}[^\\"]+)""",
   """"+path\\"+:\\"+\\+({path}[^"]+)\\"+""",
   """"+action type\\"+:\\"+({activity}[^\\"]+)"""
 ]
}
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
  Product = PROWATCH
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