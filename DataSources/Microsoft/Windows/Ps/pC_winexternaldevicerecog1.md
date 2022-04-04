#### Parser Content
```Java
{
Name = win-external-device-recog-1
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  DataType = "usb-insert"
  Conditions = [ """EventCode=6416""", """A new external device was recognized by the system.""", """ComputerName =""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}(\d{2}\/){2}\d{4} (\d{2}:){2}\d{2} (?:am|AM|pm|PM))""",
    """ComputerName =\s{0,100}({dest_host}[^=]{1,2000}?)\s{1,100}TaskCategory=""",
    """Account Name:\s{0,100}(-\s{0,100}|({user}[^:]{1,2000}?)\s{1,100})Account Domain:""",
    """Security ID:\s{0,100}({user_sid}[^:]{1,2000}?)\s{1,100}Account Name:""",
    """Device Name:\s{0,100}({device_name}[^:]{1,2000}?)\s{1,100}Class ID:""",
    """Device ID:\s{0,100}({device_id}[^:]{1,2000}?)\s{1,100}Device Name:""",
    """Account Domain:\s{0,100}(-\s{0,100}|({domain}[^:]{1,2000}?)\s{1,100})Logon ID:""",
    """Location Information:\s{0,100}(|-|({additional_info}[^"]{0,2000}))(\s{1,100}|\s{0,100}")""",
    """Class Name:\s{0,100}({device_type}[^:]{1,2000}?)\s{1,100}(Vendor IDs:|Hardware IDs:)""",
    """hostname":"({dest_host}[^"]{1,2000})""",
    """EventCode=({event_code}\d{1,2000})\s""",
    """({event_name}A new external device was recognized by the system.)"""
  ]
  DupFields = [ "event_name->activity" ]


}
```