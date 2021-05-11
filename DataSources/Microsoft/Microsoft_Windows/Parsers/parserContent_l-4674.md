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
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{0,100}Z+)'/>""",
    """<Keywords>({outcome}[^<]+?)</Keywords>""",
    """<Computer>({host}({dest_host}[\w\-]+)[\w.\-]*)</Computer>""",
    """({event_code}4674)""",
    """Process Name:\s{0,100}(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s{0,100}Requested""",
    """Account Name:\s{0,100}(?:-|({user}[^:<]+?))\s{0,100}Account Domain:""",
    """Account Domain:\s{0,100}({domain}[^:]+?)\s{0,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}[^:]+?)\s{0,100}Object:""",
    """Object Server:\s{0,100}({object_server}[^:]+?)\s{0,100}Object Type:""",
    """Object Type:\s{0,100}(?:-|({object_type}[^:]+?))\s{0,100}Object Name:""",
    """Object Name:\s{0,100}(?:|-|({object}[^<>]+?))\s{0,100}Object Handle""",
    """Desired Access:\s{0,100}({accesses}[^:]+?)\s{0,100}Privileges:""",
    """Privileges:\s{0,100}({privileges}[^:<>]+?)(\s{0,100}<|\s{0,100}$)"""   
  ]
  DupFields = [ "directory->process_directory" ]
}
```