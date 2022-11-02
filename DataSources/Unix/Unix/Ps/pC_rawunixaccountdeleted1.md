#### Parser Content
```Java
{
Name = raw-unix-account-deleted-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-deleted"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ delete """, """ userdel[""",""" group '""" ]
  Fields = [
    """\d\d:\d\d:\d\d(\.\S{1,2000})? ({host}[\w.\-]{1,2000})\suserdel""",
    """delete\s{1,100}\'({target_user}[^']{1,2000})\'""",
    """group\s{1,100}'({group_name}[^']{1,2000})'"""
  ]
  DupFields=["host->dest_host", "target_user->account_name"]


}
```