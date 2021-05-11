#### Parser Content
```Java
{
Name = syslog-l7-app-activity-get
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """l7log:""" , "User ", """ requested GET """ ]
  Fields = [
    """exabeam_host=({host}[\w\-\.]+)""",
    """\s({host}[\w\-\.]+?)\s{1,100}\w+\d{1,100}\s{1,100}\-\s{1,100}l7log:""",
    """\d{1,100}log:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100}):\s{0,100}\(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})\)""",
    """\sUser\s{0,100}\'(({domain}[^']+)\\)?({user}[^']+)\'""",
    """\sUser\s{0,100}\'({user_email}[^\s@]+@[^\s@]+)\'""",
    """\sUser\s{0,100}\'({user}[^\s@]+@[^\s]+)\'""",
    """\srequested ({activity}GET) ({object}.+?)\s{0,100}$""",
  ]
}
```