#### Parser Content
```Java
{
Name = auditbeat-security-alert
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["susp_activity""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}susp_activity)""",
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
    """"end":({time}\d{1,100})""",
    """"actor":\{.*?"secondary":"(|({user}[^"]+))""""
    """"actor":\{.*?"primary":"(|({account}[^"]+))""""
    """"user":\{.*?"uid":"({user_id}\d{1,100})"""",
    """"user":\{.*?"gid":"({group_id}\d{1,100})"""",
    """"pid":({pid}\d{1,100})""",
    """"ppid":({parent_process_id}\d{1,100})""",
    """"process":\{.*?"name":"(|({process_name}[^"]+))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]+?)\]""",
    """"process":\{.*?"title":"({command_line}.*?)"(\}|,)"""
    """"host":\{.*?"name":"(|({host}[^"]+))"""",
    """"data":\{.*?"hostname":"(eth\d{1,100}\.)?(|({src_host}[^"]+))"""",
    """"result":"({outcome}[^"]+)"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]+))"""",
    """"event":\{.*?"action":"(|({log_type}[^"]+))"""",
    """"event":\{.*?"category":"(|({sub_event_type}[^"]+))"""",
    """"event":\{.*?"outcome":"(|({outcome}[^"]+))"""",
    """"source":\{"ip":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"process":\{.*?"executable":"(|({service}[^"]+))"""",
    """"file":\{.*?"path":"(|({file_path}[^"]+))"""",
    """"file":\{.*?"owner":"(|({file_owner}[^"]+))"""" 
 ]

```