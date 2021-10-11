#### Parser Content
```Java
{
Name = symantec-usb-delete
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ",Rule: ", ",File Delete,Begin:"]
  Fields = [
    """exabeam_host=({host}[^,\s]{1,2000})""",
    """,(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]{0,2000})),([^,]{0,2000},){2}File Delete,""",
    """,Rule:[^\|]{0,2000}\| ({activity_details}[^,]{0,2000})""",
    """Begin:\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,File Delete,([^,]{0,2000},){3}\d{1,100},"?(?: |({process}({directory}(?:[^,]{1,2000})?[\\\/])?({process_name}[^\\\/,]{1,2000}?))),\d{1,100},[^,]{1,2000},"?({file_path}.+?)"?,User""",
    """,File Delete,([^,]{0,2000},){3}\d{1,100},[^,]{0,2000},\d{1,100},[^,]{1,2000},.*/({file_name}.+?)"?,User""",
    """User:\s{1,100}({user}.+?),Domain""",
    """({activity}File Delete)""",
    """Domain:\s{1,100}({domain}.+?),Action Type""",
    """File size \(bytes\):\s{1,100}({bytes}\d{1,100})""",
    """Device ID:\s{1,100}({device_id}.*)&\d{1,100}""",
    """({device_type}(CD-DVD|USB))"""
  ]
  DupFields = ["directory->process_directory"]
}
```