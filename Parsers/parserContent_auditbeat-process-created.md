#### Parser Content
```Java
{
Name = auditbeat-process-created
  Vendor = Unix
  Product = Auditbeat
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""auditbeat"""",""""action":"process_started"""",""""process":""",""""pid":"""]
  Fields = [
    """timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)"""",
    """"hostname":"({host}[^"]+)""""
    """"action":"({event_name}[^"]+)"""",
    """"pid":({pid}\d+)""",
    """"process".+?"executable":"({process}(({process_directory}[^"]*?)\/)?[^"\\\/]*?)"""",
    """"process":.+?"name":"({process_name}[^"]+)"""",
    """"ppid":({parent_process_id}\d+)""",
    """"message":"({additional_info}[^"]+)"""",
    """"args":\["({command_line}[^"]+)""""
    """"md5":"({md5}[^"]+)"""",
    """user.+?group":.+?id":"({user_id}\d+)"""",
    """user.+?group":.+?name":"({user}[^"]+)""""
  ]
  DupFields = ["process->path","host->dest_host","process_directory->directory"]
}
```