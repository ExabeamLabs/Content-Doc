#### Parser Content
```Java
{
Name = auditbeat-security-alert-2
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["unauthedfileaccess""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}unauthedfileaccess)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
auditbeat-events = {
  Vendor = Unix
  Product = Unix
  Lms = Direct
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """"end":({time}\d+)""",
    """"actor":\{.*?"secondary":"(|({user}[^"]+))""""
    """"actor":\{.*?"primary":"(|({account}[^"]+))""""
    """"user":\{.*?"uid":"({user_id}\d+)"""",
    """"user":\{.*?"gid":"({group_id}\d+)"""",
    """"pid":({pid}\d+)""",
    """"ppid":({parent_process_id}\d+)""",
    """"process":\{.*?"name":"(|({process_name}[^"]+))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]+?)\]""",
    """"process":\{.*?"title":"({command_line}.*?)"(\}|,)"""
    """"host":\{.*?"name":"(|({host}[^"]+))"""",
    """"data":\{.*?"hostname":"(eth\d+\.)?(|({src_host}[^"]+))"""",
    """"result":"({outcome}[^"]+)"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]+))"""",
    """"event":\{.*?"action":"(|({event_type}[^"]+))"""",
    """"event":\{.*?"category":"(|({sub_event_type}[^"]+))"""",
    """"event":\{.*?"outcome":"(|({outcome}[^"]+))"""",
    """"source":\{"ip":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"process":\{.*?"executable":"(|({service}[^"]+))"""",
    """"file":\{.*?"path":"(|({file_path}[^"]+))"""",
    """"file":\{.*?"owner":"(|({file_owner}[^"]+))"""" 
 ]

```