#### Parser Content
```Java
{
Name = u-googledrive-file-activity
  Vendor = Google
  Product = Google Drive
  Lms = Sumo
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"drive"""", """"uniqueQualifier":""",  """"access"""" ]
  Fields = [
    """exabeam_host=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress":"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId":"({user_id}\d+)""",
    """"actor":\{[^=]*?"email":"(({user_email}[^@"]+@[^@"]+)|({user}[^@"\s]+))"""",
    """"events":[^=]*?"name"\s*:\s*"old_value",\s*"multiValue"\s*:\s*\[\s*"({src_file_name}[^"]+)"""",
    """"events":[^=]*?"name"\s*:\s*"new_value",\s*"multiValue"\s*:\s*\[\s*"\s*({file_name}[^"]+?)\s*"""",
    """"events":[^=]*?"name":"({accesses}[^"]+)"""",
    """"events":[^=]*?"type":"access","name":"({accesses}[^"]+)"""",
    """"events":[^=]*?"name"\s*:\s*"destination_folder_title",\s*"value"\s*:\s*"({file_parent}[^"]+)"""",
    """"events":[^=]*?"name"\s*:\s*"source_folder_title",\s*"value"\s*:\s*"({src_file_dir}[^"]+)"""",
    """"events":[^=]*?"name":"doc_id","value":"({file_id}[^"]+)"[^=]*?"name":"doc_type","value":"(unknown|({file_type}[^"]+))"[^=]*?"name":"doc_title","value":"\s*({file_name}[^"]+?(\.({file_ext}[^."]{1,6}))?)\s*"[^=]*?"name":"visibility","value":"({privileges}[^"]+)"[^=]*?"name":"owner","value":"({file_owner}[^"]+?)\s*"""",
  ]
  DupFields = [ "file_name->object" ]
}
```