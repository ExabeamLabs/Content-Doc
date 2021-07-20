#### Parser Content
```Java
{
Name = vmware-horizon-logon
  Vendor = VMware
  Product = VMware Horizon
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ View """ , """ Severity""" , """ Module""" , """EventType=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})""",
    """({app}View)""",
    """EventType="{0,20}({event_name}[^"]{1,2000})"""
    """UserDisplayName="{0,20}(({domain}[^\\"]{1,2000})\\+)?({user}[^\\"]{1,2000})"""",
    """SessionType="{0,20}({activity}[^"]{1,2000})""",
    """UserSID="{0,20}({user_sid}[^"]{1,2000})""",
    """Module="{0,20}({resource}[^"]{1,2000})""",
    """ApplicationId="{0,20}({object}[^"]{1,2000})"""
  ]
}
```