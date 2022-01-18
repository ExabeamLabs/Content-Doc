#### Parser Content
```Java
{
Name = u-googledrive-file-permission-change
  Vendor = Google
  Product = Google Drive
  Lms = Sumo
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"drive"""", """"uniqueQualifier":""",  """"acl_change"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    ""","time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    ""","ipAddress":"({src_ip}[\da-fA-F\.:]{1,2000})"""",
    ""","profileId":"({user_id}\d{1,100})""",
    """"type":"acl_change"[^=]{0,2000}?"name":"({accesses}[^"]{1,2000})"""",
    """"events":[^\}\]]{0,2000}?"name":"({accesses}[^"]{1,2000})[^=]{0,2000}?"""",
    """:"({app}drive)""",
    ""","parameters":[^=]{0,200}?name":"target_user","value":"(({user_email}[^@",\s]{1,200}@[^@",\s]{1,200})|({user}[^@",\s]{1,200}))"[^=]{0,200}?"""",
    ""","parameters":[^=]{0,2000}?name":"doc_id","value":"({file_id}[^"]{1,200})"[^=]{0,200}?name":"doc_type","value":"((?i)unknown|({file_type}[^"]{1,200}))"[^=]{0,200}?name":"doc_title","value":"({file_name}[^"]{1,200}?(\.\s{0,100}({file_ext}[a-zA-Z]{1,200}?))?)\s{0,100}"[^=]{0,200}?name":"visibility","value":"({privileges}[^"]{1,200})"[^=]{0,200}?name":"owner","value":"({file_owner}[^"]{1,200})\s{0,100}"""",
  ]
  DupFields = [ "file_name->object", "privileges->activity"  ]


}
```