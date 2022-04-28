#### Parser Content
```Java
{
Name = progress-db-remote-logon
  Vendor = Progress
  Product = Progress Database
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'@'HH:mm:ss.SSSZ"
  Conditions = [ """ T-""", """ P-""", """(742)""", """ Login """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """:\d\d:\d\d\s{1,100}({src_host}[^\s]{1,2000})\s{1,100}\[({time}\d\d\d\d\/\d\d\/\d\d@\d\d:\d\d:\d\d\.\d\d\d-\d\d\d\d)\]\s{1,100}({pid}[^\s]{1,2000})\s{1,100}({thread_id}[^\s]{1,2000})\s{1,100}({severity}[^\s]{1,2000})\s{1,100}({service_name}TSRV)\s{1,100}\d:\s{0,100}\(({event_code}742)\)\s{1,100}({additional_info}({event_name}Login)[^,]{1,100}),\s{1,100}userid\s({user}[^\s]{1,2000})[^,]{1,100

}
```