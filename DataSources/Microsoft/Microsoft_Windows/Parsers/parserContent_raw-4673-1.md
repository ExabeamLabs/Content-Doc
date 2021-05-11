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
    """({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\d{1,100})\s{1,100}4673""",
    """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information))\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}({host}[^=]+?)\s{0,100}(\s|\t|,|#\d{1,100}|<[^>]+>)\s{0,100}""",
    """({event_code}4673)""",
    """Process Name:\s{0,100}(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))[\s;]*Service Request Information:""",
    """Account Name:\s{0,100}({user}[^:]+?)\s{0,100}Account Domain:""",
    """Account Domain:\s{0,100}({domain}[^:]+?)\s{0,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}[^:]+?)\s{0,100}Service:""",
    """Server:\s{0,100}({object_server}[^:]+?)\s{0,100}Service Name:""",
    """Privileges:\s{0,100}({privileges}[^$]+?)(\s{0,100}$|\s{1,100}\d{1,100}|\"|,|;)""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
  ]
  DupFields = ["directory->process_directory"]
}
```