#### Parser Content
```Java
{
Name = netskope-activity
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [  """"session_begin"""",""""activity"""",""""object_id"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"dstip": "({host}[^"]+)"""",
    """"timestamp": ({time}\d+)""",
    """"user": "({account}[^"]+)"""",
    """"app": "({app}[^"]+)"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"browser": "(unknown|({browser}[^"]+))"""",
    """"os"+: "(unknown|({os}[^"]+))"""",
    """"activity": "({activity}[^"]+)"""",
    """"from_user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"from_user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """"object": ["\\:, ]+({file_name}.+?)["\\:, ]+, """",
    """"object_type": "({file_type}[^"]+)"""",
    """"url": "({additional_info}[^"]+)""""
  ]
   DupFields=["file_name->object_value",
     "additional_info->file_parent",
     "browser->user_agent",
     "activity->accesses"]
}
```