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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\s({host}[\w\-\.]+)\s{1,100}\S+\s{1,100}\-\s{1,100}ssomgr:""",
    """\[host=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\[user=(({domain}[^\\]+)\\)?({user}[^\]]+)\]""",
    """\[user=({user_email}[^@]+@({email_domain}[^@\]\s]+))\]""",
    """\[user=({user}[^@]+@[^@\]\s]+)\]""",
    """\sssomgr:\s{0,100}({activity}.+?)\s{0,100}\["""
  ]
}
```