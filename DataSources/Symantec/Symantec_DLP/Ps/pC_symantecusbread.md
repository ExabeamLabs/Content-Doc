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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """,(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]{0,2000})),([^,]{0,2000},){2}File Read""",
    """Rule:[^\|]{0,2000}\|\s{0,100}({activity_details}[^,]{1,2000})""",
    """User:\s{0,100}(SYSTEM|({user}[^\s,]{1,2000}))""",
    """Domain:\s{0,100}({domain}[^,]{1,2000})""",
    """,File Read,([^,]{0,2000},){3}\d{1,100},"?(?: |({process}({directory}(?:[^,"]{1,2000})?[\\\/])?({process_name}[^\\\/,"]{1,2000}?))),\d{1,100},[^,]{1,2000},"?({file_path}[^"]{0,2000}?)"?\s{0,100},User""",
    """,File Read,([^,]{0,2000},){3}\d{1,100},[^,]{0,2000},\d{1,100},[^,]{1,2000},.*/(|({file_name}[^"]{0,2000}?))"?\s{0,100},User""",
    """File size \(bytes\):\s{0,100}({bytes}\d{1,100})""",
    """({activity}File Read)""",
    """({device_type}(CD-DVD|USB))""",
    """Device ID:\s{0,100}({device_id}.*)&\d{1,100}""",
  ]
  DupFields = ["directory->process_directory"]
}
```