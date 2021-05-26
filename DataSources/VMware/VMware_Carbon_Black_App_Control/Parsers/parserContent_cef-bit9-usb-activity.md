#### Parser Content
```Java
{
Name = cef-bit9-usb-activity
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", "tached|" ]
  Fields = [
    """({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({activity}[^\|]{1,2000})\|""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s{0,100}$)""",
    """(\||\s)msg=({activity_details}.+?)\.\s""",
    """(\||\s)msg=Device\s{1,100}'({device_id}.+?)'""",
    """(\||\s)msg=Device\s{1,100}'({device_id}[^']{1,2000}?)\s{0,100}\([^']{1,2000}'""",
  ]
}
```