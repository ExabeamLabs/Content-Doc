#### Parser Content
```Java
{
Name = json-auditd-process-creation
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""type":"syscall"""", """auditd"""]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"name_map":\{.*?"uid":"(|({user}[^"]+))"""",
    """"name_map":\{.*?"suid":"(|({account}[^"]+))"""",
    """"user":\{.*?"uid":"({user_id}\d+)"""",
    """"user":\{.*?"auid":"({account_used_id}\d+)"""",
    """"user":\{.*?"gid":"({group_id}\d+)"""",
    """"pid":"({pid}\d+)""",
    """"ppid":"({parent_process_id}\d+)""",
    """"process":\{.*?"name":"(|({process_name}[^"]+))"""",
    """"process":\{.*?"exe":"(|({process}({process_directory}[^"]+\/).*?))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]+?)\]""",
    """"host":\{.*?"name":"(|({host}[^"]+))"""",
    """"result":"({outcome}[^"]+)"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]+))""""
 ]
 DupFields = [ "process_directory->directory", "process->path", "host->dest_host", "pid->process_id" ]
}
```