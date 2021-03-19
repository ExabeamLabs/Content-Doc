#### Parser Content
```Java
{
Name = l-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS Z"
  Conditions = [ """An operation was attempted on a privileged object.""", """<EventID>4674</EventID>""" ]
  Fields = [
    """({event_name}An operation was attempted on a privileged object)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d*Z+)'/>""",
    """<Keywords>({outcome}[^<]+?)</Keywords>""",
    """<Computer>({host}({dest_host}[\w\-]+)[\w.\-]*)</Computer>""",
    """({event_code}4674)""",
    """Process Name:\s*(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s*Requested""",
    """Account Name:\s*(?:-|({user}[^:<]+?))\s*Account Domain:""",
    """Account Domain:\s*({domain}[^:]+?)\s*Logon ID:""",
    """Logon ID:\s*({logon_id}[^:]+?)\s*Object:""",
    """Object Server:\s*({object_server}[^:]+?)\s*Object Type:""",
    """Object Type:\s*(?:-|({object_type}[^:]+?))\s*Object Name:""",
    """Object Name:\s*(?:|-|({object}[^<>]+?))\s*Object Handle""",
    """Desired Access:\s*({accesses}[^:]+?)\s*Privileges:""",
    """Privileges:\s*({privileges}[^:<>]+?)(\s*<|\s*$)"""   
  ]
  DupFields = [ "directory->process_directory" ]
}
```