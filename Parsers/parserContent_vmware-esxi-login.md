#### Parser Content
```Java
{
Name = vmware-esxi-login
  Vendor = VMware ESXi
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
```