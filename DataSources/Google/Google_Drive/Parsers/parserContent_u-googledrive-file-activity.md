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
    ""","time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    ""","ipAddress":"({src_ip}[\da-fA-F\.:]+)"""",
    ""","profileId":"({user_id}\d{1,100})""",
    """"actor":\{[^=]*?"email":"(({user_email}[^@"]+@[^@"]+)|({user}[^@"\s]+))"""",
    ""","events":[^=]*?"name"\s{0,100}:\s{0,100}"old_value",\s{0,100}"multiValue"\s{0,100}:\s{0,100}\[\s{0,100}"({src_file_name}[^"]+)"""",
    ""","events":[^=]*?"name"\s{0,100}:\s{0,100}"new_value",\s{0,100}"multiValue"\s{0,100}:\s{0,100}\[\s{0,100}"\s{0,100}({file_name}[^"]+?)\s{0,100}"""",
    ""","events":[^=]*?"name":"({accesses}[^"]+)"""",
    ""","events":[^=]*?"type":"access","name":"({accesses}[^"]+)"""",
    ""","events":[^=]*?"name"\s{0,100}:\s{0,100}"destination_folder_title",\s{0,100}"value"\s{0,100}:\s{0,100}"({file_parent}[^"]+)"""",
    ""","events":[^=]*?"name"\s{0,100}:\s{0,100}"source_folder_title",\s{0,100}"value"\s{0,100}:\s{0,100}"({src_file_dir}[^"]+)"""",
    ""","events":[^=]*?"name":"doc_id","value":"({file_id}[^"]+)"[^=]*?"name":"doc_type","value":"(unknown|({file_type}[^"]+))"[^=]*?"name":"doc_title","value":"\s{0,100}({file_name}[^"]+?(\.({file_ext}[^."]{1,6}?))?)\s{0,100}"[^=]*?"name":"visibility","value":"({privileges}[^"]+)"[^=]*?"name":"owner","value":"\s{0,100}({file_owner}[^"]+?)\s{0,100}"""",
  ]
  DupFields = [ "file_name->object" ]
}
```