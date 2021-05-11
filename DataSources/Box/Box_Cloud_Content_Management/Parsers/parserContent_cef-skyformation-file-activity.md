#### Parser Content
```Java
{
Name = cef-skyformation-file-activity
  Vendor = Box
  Product = Box Cloud Content Management
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"event_type":"MOVE"""", """"type":"event"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"created_at":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """"source":.*?"item_name":"({file_name}[^",]+)""",
    """"source":.*?"item_type":"({file_type}[^",]+)""",
    """"login":"({user}[^\s",@]+)"""",
    """"login":"({user_email}[^\s",@]+@[^\s",@]+)""",
    """"event_type":"({accesses}[^",]+)""",
    """"ip_address":"({src_ip}[^",]+)""",
    """"parent":.*?"name":"({file_parent}[^",]+)""",
    """"service_name":"({process_name}[^",]+)""",
    """"size":({bytes}\d{1,100})""",
    """({app}Box)""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]name"{1,20}\s{0,100}:\s{0,100}"{1,20}({user_fullname}[^":,]+)[",\]\}]""",
    """[^\w]created_by"{1,20}\s{0,100}:\s{0,100}[^\}]+?[^\w]login"{1,20}\s{0,100}:\s{0,100}"{1,20}.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))""",
    """owned_by"{1,20}:.+?"login"{1,20}:"{1,20}({target_user}[^\s@"]+@[^\s@"]+)"""
  ]
}
```