#### Parser Content
```Java
{
Name = vmware-esxi-login
  Vendor = VMware
  Product = VMware ESXi
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """][""", """ User """, """ logged in """, """ESX""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).+?\s+({host}[^\s]+)\s""",
    """User\s+((({domain}[^\\\s@]+)\\+)?({user}[^\s\\@]+)).+?\s*logged""",
    """({event_name}logged in)""",
    """:\s+({additional_info}User.+?)\s*$""",
    """logged in\s*as\s*({user_agent}.+?)\s*$""",
    """logged in as\s(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """({app}ESX)"""
  ]
  DupFields = [ "event_name->activity", "host->dest_host" ]
}
{
  Name = vmware-esxi-login-1
  Vendor = VMware
  Product = VMware ESXi
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""" logged in """,""" [User ""","""Event [""",""" vpxd """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).+?\s+({host}[^\s]+)\s""",
    """User\s+((({domain}[^\\\s@]+)\\+)?({user}[^\s\\@]+)).+?\s*logged""",
    """\[({event_name}User.+?logged (out|in))""",
    """user agent:\s+({user_agent}[^)]+)"""
    """\w+@(127.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]
  DupFields = [ "event_name->activity", "host->dest_host" ]
}
{
  Name = vmware-vcenter-activity
  Vendor = VMware
  Product = VMware VCenter
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ VIEWCENTER """ , """] [""" ]
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """host":"({host}[^"]+)"""
      """vim.event.({activity}[^\s\]]+)"""
      """\[User\s([\w\.]+\\+)?({user}[^\s@\]]+).+?\s"""
      """\[User.+?@({src_ip}[^\s\]]+)""",
      """({app}VM_VCenter)"""
  ]
}

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