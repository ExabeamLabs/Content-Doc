#### Parser Content
```Java
{
Name = auditd-unix-account-switch
  Vendor = Unix
  Product = Auditd
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """audispd""", """USER_ROLE_CHANGE""" , """ auid=""" ]
  Fields = [
    """node=({host}[^\s\.]+)"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
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