#### Parser Content
```Java
{
Name = u-googledrive-file-permission-change
  Vendor = Google
  Lms = Sumo
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"drive"""", """"uniqueQualifier":""",  """"acl_change"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"events"\s*:.*?\s*"name"\s*:\s*"({accesses}[^"]+).*?"type"\s*:\s*"acl_change"""",
    """"events"\s*:.*?"type"\s*:\s*"acl_change",\s*"name"\s*:\s*"({accesses}[^"]+)"""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}[^@"]+@[^"]+)"""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user}[^@"\s]+)"""",
    """"events":.*?"name"\s*:\s*"doc_id",\s*"value"\s*:\s*"({file_id}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"doc_type",\s*"value"\s*:\s*"({file_type}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"doc_title",\s*"value"\s*:\s*"({file_name}[^"]+?(\.\s*({file_ext}[^."]+?))?)\s*"""",
    """"events":.*?"name"\s*:\s*"visibility",\s*"value"\s*:\s*"({privileges}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"owner",\s*"value"\s*:\s*"({file_owner}[^"]+)"""",
  ]
  DupFields = [ "file_name->object", "host->dest_host" ]
}
```