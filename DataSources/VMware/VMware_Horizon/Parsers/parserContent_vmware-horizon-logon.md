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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)""",
    """({app}View)""",
    """EventType="{0,20}({event_name}[^"]+)"""
    """UserDisplayName="{0,20}(({domain}[^\\"]+)\\+)?({user}[^\\"]+)"""",
    """SessionType="{0,20}({activity}[^"]+)""",
    """UserSID="{0,20}({user_sid}[^"]+)""",
    """Module="{0,20}({resource}[^"]+)""",
    """ApplicationId="{0,20}({object}[^"]+)"""
  ]
}
```