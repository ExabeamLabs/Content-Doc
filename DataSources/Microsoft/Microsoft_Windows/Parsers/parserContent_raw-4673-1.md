#### Parser Content
```Java
{
Name = raw-4673-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["A privileged service was called", "Privileges", "Account Name:"]
  Fields = [
    """({event_name}A privileged service was called)""",
    """({time}\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+4673""",
    """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s*(\s|\t|,|#\d+|<[^>]+>)\s*({host}[^=]+?)\s*(\s|\t|,|#\d+|<[^>]+>)\s*""",
    """({event_code}4673)""",
    """Process Name:\s*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information:""",
    """Account Name:\s*({user}[^:]+?)\s*Account Domain:""",
    """Account Domain:\s*({domain}[^:]+?)\s*Logon ID:""",
    """Logon ID:\s*({logon_id}[^:]+?)\s*Service:""",
    """Server:\s*({object_server}[^:]+?)\s*Service Name:""",
    """Privileges:\s*({privileges}[^$]+?)(\s*$|\s+\d+|\"|,|;)""",
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
  ]
  DupFields = ["directory->process_directory"]
}
```