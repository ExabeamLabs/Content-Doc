#### Parser Content
```Java
{
Name = anywhere365-app-activity-1
  Conditions = [""" Ucc Call received from: """]
  Vendor = Anywhere365
  Product = Anywhere365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\s({log_id}\w+-\w+-\w+-\w+-\w+)\s""",
    """Call received from:\s{0,100}sip:(({user_email}[^@]{1,2000}@[^,\s;'']{1,2000})[,;\s]|({user}[^\s,]{1,2000}))""",
  ]
  DupFields = ["user_email->caller_user", "user->caller_user"]
}
```