#### Parser Content
```Java
{
Name = cef-carbonblack-usb-activity
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", "tached|" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({activity}[^\|]+)\|""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s+[\w-]+=|\s*$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s+(\w+=|$)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s+(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s*$)""",
    """(\||\s)msg=({activity_details}.+?)\.\s""",
    """(\||\s)msg=Device\s+'({device_id}.+?)'""",
    """(\||\s)msg=Device\s+'({device_id}[^']+?)\s*\([^']+'""",
  ]
}
```