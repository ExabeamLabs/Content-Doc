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
    """timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""",
    """"hostname":"({host}[^"]{1,2000})""""
    """"action":"({event_name}[^"]{1,2000})"""",
    """"pid":({pid}\d{1,100})""",
    """"process".+?"executable":"({process}(({process_directory}[^"]{0,2000}?)\/)?[^"\\\/]{0,2000}?)"""",
    """"process":.+?"name":"({process_name}[^"]{1,2000})"""",
    """"ppid":({parent_process_id}\d{1,100})""",
    """"message":"({additional_info}[^"]{1,2000})"""",
    """"args":\["({command_line}[^"]{1,2000})""""
    """"md5":"({md5}[^"]{1,2000})"""",
    """user.+?group":.+?id":"({user_id}\d{1,100})"""",
    """user.+?group":.+?name":"({user}[^"]{1,2000})""""
  ]
  DupFields = ["process->path","host->dest_host","process_directory->directory"]
}
```