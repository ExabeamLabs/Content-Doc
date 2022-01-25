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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).+?\s{1,100}({host}[^\s]{1,2000})\s""",
    """User\s{1,100}((({domain}[^\\\s@]{1,2000})\\+)?({user}[^\s\\@]{1,2000})).+?\s{0,100}logged""",
    """({event_name}logged in)""",
    """:\s{1,100}({additional_info}User.+?)\s{0,100}$""",
    """logged in\s{0,100}as\s{0,100}({user_agent}.+?)\s{0,100}$""",
    """logged in as\s(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """({app}ESX)"""
  ]
  DupFields = [ "event_name->activity", "host->dest_host" ]


}
```