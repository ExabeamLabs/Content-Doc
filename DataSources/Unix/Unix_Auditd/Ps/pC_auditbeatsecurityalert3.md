#### Parser Content
```Java
{
Name = auditbeat-security-alert-3
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["recon""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}recon)""",
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
    """"actor":\{.*?"secondary":"(|({user}[^"]{1,2000}))""""
    """"actor":\{.*?"primary":"(|({account}[^"]{1,2000}))""""
    """"user":\{.*?"uid":"({user_id}\d{1,100})"""",
    """"user":\{.*?"gid":"({group_id}\d{1,100})"""",
    """"pid":({pid}\d{1,100})""",
    """"ppid":({parent_process_id}\d{1,100})""",
    """"process":\{.*?"name":"(|({process_name}[^"]{1,2000}))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]{1,2000}?)\]""",
    """"process":\{.*?"title":"({command_line}.*?)"(\}|,)"""
    """"host":\{.*?"name":"(|({host}[^"]{1,2000}))"""",
    """"data":\{.*?"hostname":"(eth\d{1,100}\.)?(|({src_host}[^"]{1,2000}))"""",
    """"result":"({outcome}[^"]{1,2000})"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]{1,2000}))"""",
    """"event":\{.*?"action":"(|({log_type}[^"]{1,2000}))"""",
    """"event":\{.*?"category":"(|({sub_event_type}[^"]{1,2000}))"""",
    """"event":\{.*?"outcome":"(|({outcome}[^"]{1,2000}))"""",
    """"source":\{"ip":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"process":\{.*?"executable":"(|({service}[^"]{1,2000}))"""",
    """"file":\{.*?"path":"(|({file_path}[^"]{1,2000}))"""",
    """"file":\{.*?"owner":"(|({file_owner}[^"]{1,2000}))"""" 
 ]

```