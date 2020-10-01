#### Parser Content
```Java
{
Name = symantec-usb-read
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Rule:""", """,File Read,Begin:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """Begin:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """,(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]*)),([^,]*,){2}File Read""",
    """Rule:[^\|]*\|\s*({activity_details}[^,]+)""",
    """User:\s*(SYSTEM|({user}[^\s,]+))""",
    """Domain:\s*({domain}[^,]+)""",
    """,File Read,([^,]*,){3}\d+,"?(?: |({process}({directory}(?:[^,"]+)?[\\\/])?({process_name}[^\\\/,"]+?))),\d+,[^,]+,"?({file_path}[^"]*?)"?\s*,User""",
    """,File Read,([^,]*,){3}\d+,[^,]*,\d+,[^,]+,.*/(|({file_name}[^"]*?))"?\s*,User""",
    """File size \(bytes\):\s*({bytes}\d+)""",
    """({activity}File Read)""",
    """({device_type}(CD-DVD|USB))""",
    """Device ID:\s*({device_id}.*)&\d+""",
  ]
  DupFields = ["directory->process_directory"]
}
```