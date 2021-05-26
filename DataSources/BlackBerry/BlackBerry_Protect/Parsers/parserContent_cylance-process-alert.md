#### Parser Content
```Java
{
Name = cylance-process-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Cylance Protect""", """MEMORY_VIOLATION""", """outcome=terminate""", """|security-threat-detected|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """created":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"user_name":"({user}[^"]{1,2000})"""",
    """"process_id":({pid}\d{1,100})""",
    """"image_name":"({process}({directory}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({process_name}[^\\\/"\]]{1,2000}?))"""",
    """"file_hash_id":"({sha256_sum}[^"]{1,2000})"""",
    """"groups":"({user_group}[^"]{1,2000})"""",
    """"device_id":"({device_id}[^"]{1,2000})"""",
    """outcome=({outcome}terminate)""",
    """ Category \[({alert_name}[^\]]{1,2000})\]""",
    """msg=({alert_type}[^:]{1,2000})""",
    """"agent_event_id":"({alert_id}[^"]{1,2000})"""",
    """"file_hash_id":"({file_hash}[^"]{1,2000})"""",
    """\sfname=([^=]{0,2000}\\)?({file_name}[^\.]{1,2000}\.({file_ext}[^\\:\s.]{1,2000})?)\s{1,100}\w+="""
  ]
  DupFields = [ "directory->process_directory", "file_hash->sha256_at", "file_name->name_at" ]
}
```