#### Parser Content
```Java
{
Name = win-enable-device-request
  DataType = "usb-activity"
  Conditions = [ """A request was made to enable a device.""" ]
  Fields = ${WinParserTemplates.d-xml-windows-device.Fields} [
    """({event_code}6421)""",
    """>({event_code}6421)<\/EventID>"""
    """({event_name}A request was made to enable a device.)"""
  ]

d-xml-windows-device = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>"""
    """<Computer>({dest_host}[^<>"']+?)<\/Computer>"""
    """Security ID:\s{1,100}({user_sid}[^\s]{1,2000}?)\s{1,100}Account Name:"""
    """Account Name:\s{1,100}(-\s{0,100}|({user}.*?)\s{1,100})Account Domain:"""
    """Device Name:\s{1,100}({device_name}.*?)\s{1,100}Class ID:"""
    """Device ID:\s{1,100}({device_id}.*?)\s{1,100}Device Name:"""    
    """Account Domain:\s{1,100}(-\s{0,100}|({domain}.*?)\s{1,100})Logon ID:"""    
    """Location Information:\s{1,100}(|-|({additional_info}[^\s]{0,2000}?))(\s{1,100}|\s{0,100}")"""  
    """Class Name:\s{1,100}({device_type}.*?)\s{1,100}(Vendor IDs:|Hardware IDs:)"""   
  
}
```