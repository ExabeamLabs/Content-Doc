#### Parser Content
```Java
{
Name = syslog-l7-app-activity-post
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """l7log:""" , "User ", """ requested POST """ ]
  Fields = [
    """exabeam_host=({host}[\w\-\.]{1,2000})""",
    """\s({host}[\w\-\.]{1,2000})\s{1,100}\w+\d{1,100}\s{1,100}\-\s{1,100}l7log:""",
    """\d{1,100}log:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100}):\s{0,100}\(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})\)""",
    """\sUser\s{0,100}\'(({domain}[^']{1,2000})\\)?({user}[^']{1,2000})\'""",
    """\sUser\s{0,100}\'({user_email}[^\s@]{1,2000}@({email_domain}[^\s]{1,2000}))\'""",
    """\sUser\s{0,100}\'({user}[^\s@]{1,2000}@[^\s@]{1,2000})\'""",
    """\srequested ({activity}POST) ({object}.+?)\s{0,100}$""",
  ]
}
```