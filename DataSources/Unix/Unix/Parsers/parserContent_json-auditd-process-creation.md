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
    """"@timestamp":"({time}[^"]{1,2000})""",
    """"name_map":\{.*?"uid":"(|({user}[^"]{1,2000}))"""",
    """"name_map":\{.*?"suid":"(|({account}[^"]{1,2000}))"""",
    """"user":\{.*?"uid":"({user_id}\d{1,100})"""",
    """"user":\{.*?"auid":"({account_used_id}\d{1,100})"""",
    """"user":\{.*?"gid":"({group_id}\d{1,100})"""",
    """"pid":"({pid}\d{1,100})""",
    """"ppid":"({parent_process_id}\d{1,100})""",
    """"process":\{.*?"name":"(|({process_name}[^"]{1,2000}))"""",
    """"process":\{.*?"exe":"(|({process}({process_directory}[^"]{1,2000}\/).*?))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]{1,2000}?)\]""",
    """"host":\{.*?"name":"(|({host}[^"]{1,2000}))"""",
    """"result":"({outcome}[^"]{1,2000})"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]{1,2000}))""""
 ]
 DupFields = [ "process_directory->directory", "process->path", "host->dest_host", "pid->process_id" ]
}
```