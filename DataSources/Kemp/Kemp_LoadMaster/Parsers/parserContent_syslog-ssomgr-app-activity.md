#### Parser Content
```Java
{
Name = syslog-ssomgr-app-activity
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """ssomgr: SSO-auth-token reused""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\s({host}[\w\-\.]{1,2000})\s{1,100}\S+\s{1,100}\-\s{1,100}ssomgr:""",
    """\[host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\[user=(({domain}[^\\]{1,2000})\\)?({user}[^\]]{1,2000})\]""",
    """\[user=({user_email}[^@]{1,2000}@({email_domain}[^@\]\s]{1,2000}))\]""",
    """\[user=({user}[^@]{1,2000}@[^@\]\s]{1,2000})\]""",
    """\sssomgr:\s{0,100}({activity}.+?)\s{0,100}\["""
  ]
}
```