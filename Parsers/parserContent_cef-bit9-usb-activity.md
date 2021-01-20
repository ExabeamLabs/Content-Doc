#### Parser Content
```Java
{
Name = cef-bit9-usb-activity
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", "tached|" ]
  Fields = [
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|Bit9\|Security Platform\|(.*?\|){2}({activity}[^\|]+)\|""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s+[\w-]+=|\s*$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s+(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s*$)""",
    """(\||\s)msg=({activity_details}.+?)\.\s""",
    """(\||\s)msg=Device\s+'({device_id}.+?)'""",
    """(\||\s)msg=Device\s+'({device_id}[^']+?)\s*\([^']+'""",
  ]
}
```