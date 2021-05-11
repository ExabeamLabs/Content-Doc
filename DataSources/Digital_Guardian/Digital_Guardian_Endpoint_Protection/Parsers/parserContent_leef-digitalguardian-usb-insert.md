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
    """({host}[\w\-.]+) LEEF:""",
    """\|Digital Guardian\|([^\|]*\|){2}({event_code}[^\|]+)""",
    """accountName=(({domain}[^\\\s]+)\s{0,100}\\+)?({user}[^\\\s]+?)\s{0,100}(\w+=|$)""",
    """IdentHostName=([^\\]+\\+)?({dest_host}[\w\-.]+?)\s{0,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """DestinationFile=(|({file_name}.+?(\.({file_ext}[^\.]+?))?))\s{0,100}(\w+=|$)""",
    """SourceDriveType=(|({device_type}.+?))\s{0,100}(\w+=|$)""",
    """SourceDeviceID=(|({device_id}.+?))\s{0,100}(\w+=|$)""",
    """SourceDeviceFriendlyName=(|({activity_details}.+?))\s{0,100}(\w+=|$)""",
  ]
}
```