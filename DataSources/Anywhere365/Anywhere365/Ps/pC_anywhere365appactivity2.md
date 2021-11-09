#### Parser Content
```Java
{
Name = anywhere365-app-activity-2
  Conditions = [""" UccConferenceCreator using new conference"""]
  Vendor = Anywhere365
  Product = Anywhere365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\s({log_id}\w+-\w+-\w+-\w+-\w+)\s""",
    """conference on :'({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}.)'""",
  ]
}
}
```