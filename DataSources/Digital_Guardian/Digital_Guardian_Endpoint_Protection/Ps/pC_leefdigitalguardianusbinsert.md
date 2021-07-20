#### Parser Content
```Java
{
Name = leef-digitalguardian-usb-insert
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|44|""" ]
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000}) LEEF:""",
    """\|Digital Guardian\|([^\|]{0,2000}\|){2}({event_code}[^\|]{1,2000})""",
    """accountName=(({domain}[^\\\s]{1,2000})\s{0,100}\\+)?({user}[^\\\s]{1,2000}?)\s{0,100}(\w+=|$)""",
    """IdentHostName=([^\\]{1,2000}\\+)?({dest_host}[\w\-.]{1,2000}?)\s{0,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """DestinationFile=(|({file_name}.+?(\.({file_ext}[^\.]{1,2000}?))?))\s{0,100}(\w+=|$)""",
    """SourceDriveType=(|({device_type}.+?))\s{0,100}(\w+=|$)""",
    """SourceDeviceID=(|({device_id}.+?))\s{0,100}(\w+=|$)""",
    """SourceDeviceFriendlyName=(|({activity_details}.+?))\s{0,100}(\w+=|$)""",
  ]
}
```