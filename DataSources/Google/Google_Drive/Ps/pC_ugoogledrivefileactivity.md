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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    ""","time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    ""","ipAddress":"({src_ip}[\da-fA-F\.:]{1,2000})"""",
    ""","profileId":"({user_id}\d{1,100})""",
    """"actor":\{[^=]{0,2000}?"email":"(({user_email}[^@"]{1,2000}@[^@"]{1,2000})|({user}[^@"\s]{1,2000}))"""",
    ""","events":[^=]{0,2000}?"name"\s{0,100}:\s{0,100}"old_value",\s{0,100}"multiValue"\s{0,100}:\s{0,100}\[\s{0,100}"({src_file_name}[^"]{1,2000})"""",
    ""","events":[^=]{0,2000}?"name"\s{0,100}:\s{0,100}"new_value",\s{0,100}"multiValue"\s{0,100}:\s{0,100}\[\s{0,100}"\s{0,100}({file_name}[^"]{1,2000}?)\s{0,100}"""",
    ""","events":[^=]{0,2000}?"name":"({accesses}[^"]{1,2000})"""",
    ""","events":[^=]{0,2000}?"type":"access","name":"({accesses}[^"]{1,2000})"""",
    ""","events":[^=]{0,2000}?"name"\s{0,100}:\s{0,100}"destination_folder_title",\s{0,100}"value"\s{0,100}:\s{0,100}"({file_parent}[^"]{1,2000})"""",
    ""","events":[^=]{0,2000}?"name"\s{0,100}:\s{0,100}"source_folder_title",\s{0,100}"value"\s{0,100}:\s{0,100}"({src_file_dir}[^"]{1,2000})"""",
    ""","events":[^=]{0,2000}?"name":"doc_id","value":"({file_id}[^"]{1,2000})"[^=]{0,2000}?"name":"doc_type","value":"(unknown|({file_type}[^"]{1,2000}))"[^=]{0,2000}?"name":"doc_title","value":"\s{0,100}({file_name}[^"]{1,2000}?)\s{0,100}"[^=]{0,2000}?"name":"visibility","value":"({privileges}[^"]{1,2000})"[^=]{0,2000}?"name":"owner","value":"\s{0,100}({file_owner}[^"]{1,2000}?)\s{0,100}"\

}
```