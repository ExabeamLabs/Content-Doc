#### Parser Content
```Java
{
Name = auditd-unix-account-switch
  Vendor = Unix
  Product = Unix Auditd
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """audispd""", """USER_ROLE_CHANGE""" , """ auid=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({host}[\w\-.]+)\s+audispd:""",
    """node=({host}[^\s\.]+)"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """uid=({user_id}[^\s]+)""",
    """auid=({account_used_id}[^\s]+)""",
    """pid=({process_id}[^\s]+)""",
    """exe="({process}[^"]*)"""",
    """exe="({process_directory}.+\/)({process_name}.+?)"""",
    """hostname=({src_host}[^\s\.]+)""",
    """addr=({src_ip}[^\s]+)""",
    """res=({outcome}[^\s'"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```