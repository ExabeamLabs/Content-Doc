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
    """\s({host}[\w\-.]{1,2000})\s{1,100}audispd:""",
    """node=({host}[^\s\.]{1,2000})"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """uid=({user_id}[^\s]{1,2000})""",
    """auid=({account_used_id}[^\s]{1,2000})""",
    """pid=({process_id}[^\s]{1,2000})""",
    """exe="({process}[^"]{0,2000})"""",
    """exe="({process_directory}.+\/)({process_name}.+?)"""",
    """hostname=({src_host}[^\s\.]{1,2000})""",
    """addr=({src_ip}[^\s]{1,2000})""",
    """res=({outcome}[^\s'"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```