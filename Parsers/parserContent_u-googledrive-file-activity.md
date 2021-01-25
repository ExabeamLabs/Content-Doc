#### Parser Content
```Java
{
Name = u-googledrive-file-activity
  Vendor = Google
  Lms = Sumo
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"drive"""", """"uniqueQualifier":""",  """"access"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}[^@"]+@[^"]+)"""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user}[^@"\s]+)"""",
    """"events":.*?"name"\s*:\s*"old_value",\s*"multiValue"\s*:\s*\[\s*"({src_file_name}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"new_value",\s*"multiValue"\s*:\s*\[\s*"\s*({file_name}[^"]+?)\s*"""",
    """"events"\s*:.*?\s*"name"\s*:\s*"({accesses}[^"]+).*?"type"\s*:\s*"access"""",
    """"events"\s*:.*?"type"\s*:\s*"access",\s*"name"\s*:\s*"({accesses}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"doc_id",\s*"value"\s*:\s*"({file_id}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"doc_type",\s*"value"\s*:\s*"(unknown|({file_type}[^"]+))"""",
    """"events":.*?"name"\s*:\s*"doc_title",\s*"value"\s*:\s*"\s*({file_name}[^"]+?(\.({file_ext}[^."]{1,6}))?)\s*"""",
    """"events":.*?"name"\s*:\s*"destination_folder_title",\s*"value"\s*:\s*"({file_parent}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"source_folder_title",\s*"value"\s*:\s*"({src_file_dir}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"visibility",\s*"value"\s*:\s*"({privileges}[^"]+)"""",
    """"events":.*?"name"\s*:\s*"owner",\s*"value"\s*:\s*"({file_owner}[^"]+?)\s*"""",
  ]
  DupFields = [ "file_name->object", "host->dest_host" ]
}
```