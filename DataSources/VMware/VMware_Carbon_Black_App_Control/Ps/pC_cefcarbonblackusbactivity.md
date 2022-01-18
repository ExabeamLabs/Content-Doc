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
    """\srt=({time}\d{1,100})""",
    """\|Carbon Black\|Protection\|(.*?\|){2}({activity}[^\|]{1,2000})\|""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
    """(\||\s)dhost=(|(\S+\\+)?({dest_host}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s{0,100}$)""",
    """(\||\s)msg=({activity_details}.+?)\.\s""",
    """(\||\s)msg=Device\s{1,100}'({device_id}.+?)'""",
    """(\||\s)msg=Device\s{1,100}'({device_id}[^']{1,2000}?)\s{0,100}\([^']{1,2000}'""",
  ]


}
```