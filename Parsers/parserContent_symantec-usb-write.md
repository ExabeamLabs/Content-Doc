#### Parser Content
```Java
{
Name = symantec-usb-write
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ",Rule: ", ",File Write,Begin:"]
  Fields = [
    """exabeam_host=({host}[^,\s]+)""",
    """,(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]*)),([^,]*,){2}File Write,""",
    """,Rule:[^\|]*\| ({activity_details}[^,]*)""",
    """Begin:\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,File Write,([^,]*,){3}\d+,"?(?: |({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))),\d+,[^,]+,"?({file_path}.+?)"?,User""",
    """,File Write,([^,]*,){3}\d+,[^,]*,\d+,[^,]+,.*/({file_name}.+?)"?,User""",
    """User:\s+({user}.+?),Domain""",
    """({activity}File Write)""",
    """Domain:\s+({domain}.+?),Action Type""",
    """File size \(bytes\):\s+({bytes}\d+)""",
    """Device ID:\s+({device_id}.*)&\d+""",
    """({device_type}(CD-DVD|USB))"""
  ]
  DupFields = ["directory->process_directory"]
}
```