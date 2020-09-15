#### Parser Content
```Java
{
Name = vmware-vcenter-login
  Vendor = VMware
  Product = VMware VCenter
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ VIEWCENTER """ , """Authenticated user""" ]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """host":"({host}[^"]+)"""
      """vim.event.({activity}[^\s\]]+)""",
      """Authenticated user ({user}[^\s@]+)""",
      """({app}VM_VCenter)"""
  ]
}

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
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)""",
    """({app}View)""",
    """EventType="*({event_name}[^"]+)"""
    """UserDisplayName="*(({domain}[^\\"]+)\\+)?({user}[^\\"]+)"""",
    """SessionType="*({activity}[^"]+)""",
    """UserSID="*({user_sid}[^"]+)""",
    """Module="*({resource}[^"]+)""",
    """ApplicationId="*({object}[^"]+)"""
  ]
}
```