#### Parser Content
```Java
{
Name = auditbeat-process-creation
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""logstash-auditbeat""", """"process""""]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"name_map":\{.*?"uid":"(|({user}[^"]+))"""",
    """"actor":\{[^\}]+?"secondary":"(|({user}[^"]+))""""
    """"actor":\{[^\}]+?"primary":"(|({account}[^"]+))""""
    """"name_map":\{.*?"suid":"(|({account}[^"]+))"""",
    """"user":\{.*?"uid":"({user_id}\d+)"""",
    """"user":\{.*?"auid":"({account_used_id}\d+)"""",
    """"user":\{.*?"gid":"({group_id}\d+)"""",
    """"pid":"({pid}\d+)""",
    """"ppid":"({parent_process_id}\d+)""",
    """"process":\{.*?"name":"(|({process_name}[^"]+))"""",
    """"process":\{.*?"exe":"(|({process}({process_directory}[^"]+\/).*?))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]+?)\]""",
    """"process":\{.*?"title":"({command_line}.*?)"(\}|,)"""
    """"host":\{.*?"name":"(|({host}[^"]+))"""",
    """"result":"({outcome}[^"]+)"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]+))"""",
    """"event":\{.*?"action":"(|({log_type}[^"]+))"""",
    """"event":\{.*?"category":"(|({sub_event_type}[^"]+))"""",
    """"event":\{.*?"outcome":"(|({outcome}[^"]+))"""",
    """"hostname":"({src_host}[^"]+)"""",
 ]
 DupFields = [ "process_directory->directory", "process->path", "host->dest_host", "pid->process_id" ]
}
```