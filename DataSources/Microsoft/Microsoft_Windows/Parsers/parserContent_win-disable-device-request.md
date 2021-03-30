#### Parser Content
```Java
{
Name = win-disable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to disable a device.""", """>6419</EventID>""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """>({event_code}6419)<\/EventID>"""
    """({event_name}A request was made to disable a device.)"""
  ]
}
d-xml-windows-device = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>"""
    """<Computer>({dest_host}.*?)<\/Computer>"""
    """Security ID:\s+({user_sid}[^\s]+?)\s+Account Name:"""
    """Account Name:\s+(-\s*|({user}.*?)\s+)Account Domain:"""
    """Device Name:\s+({device_name}.*?)\s+Class ID:"""
    """Device ID:\s+({device_id}.*?)\s+Device Name:"""    
    """Account Domain:\s+(-\s*|({domain}.*?)\s+)Logon ID:"""    
    """Location Information:\s+(-|({additional_info}[^\s]*?)\s+)"""  
    """Class Name:\s+({device_type}.*?)\s+(Vendor IDs:|Hardware IDs:)"""   
  ]

```