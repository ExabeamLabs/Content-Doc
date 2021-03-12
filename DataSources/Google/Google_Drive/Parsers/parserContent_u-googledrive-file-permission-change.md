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
    """exabeam_host=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress":"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId":"({user_id}\d+)""",
    """"type":"acl_change"[^=]*?"name":"({accesses}[^"]+)"""",
    """cs6=[^=]+?"events":[^\}\]]*?"name":"({accesses}[^"]+)[^=]*?"type":"acl_change"""",
    """:"({app}drive)""",
    """"parameters":[^=]*?"name":"target_user","value":"(({user_email}[^@",\s]+@[^@",\s]+)|({user}[^@",\s]+))"[^=]*?"name":"doc_id","value":"({file_id}[^"]+)"[^=]*?"name":"doc_type","value":"((?i)unknown|({file_type}[^"]+))"[^=]*?"name":"doc_title","value":"({file_name}[^"]+?(\.\s*({file_ext}[a-zA-Z]+?))?)\s*"[^=]*?"name":"visibility","value":"({privileges}[^"]+)"[^=]*?"name":"owner","value":"({file_owner}[^"]+)"""",
  ]
  DupFields = [ "file_name->object" ]
}
```