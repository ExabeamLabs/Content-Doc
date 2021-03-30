#### Parser Content
```Java
{
Name = cef-skyformation-file-activity
  Vendor = Box
  Product = Box
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"event_type":"MOVE"""", """"type":"event"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"created_at":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"source":.*?"item_name":"({file_name}[^",]+)""",
    """"source":.*?"item_type":"({file_type}[^",]+)""",
    """"login":"({user}[^\s",@]+)"""",
    """"login":"({user_email}[^\s",@]+@[^\s",@]+)""",
    """"event_type":"({accesses}[^",]+)""",
    """"ip_address":"({src_ip}[^",]+)""",
    """"parent":.*?"name":"({file_parent}[^",]+)""",
    """"service_name":"({process_name}[^",]+)""",
    """"size":({bytes}\d+)""",
    """({app}Box)""",
  ]
}
```