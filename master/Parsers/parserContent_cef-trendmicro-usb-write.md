#### Parser Content
```Java
{
Name = cef-trendmicro-usb-write
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Trend Micro|""", """flexString1=Passed""", """flexString2=Removable storage""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\scs4=({user}.+?)\s+(\w+=|$)""",
    """({activity}File Copy)""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({dest_host}.+?)\s+(\w+=|$)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^.\s]+))?)\s+(\w+=|$)""",
    """\sfilePath=({file_parent}.+?)\s+(\w+=|$)""",
    """\sflexString2=({device_type}.+?)\s+(\w+=|$)""",
    """\sflexString1=({action}.+?)\s+(\w+=|$)""",
    """\scs5=({activity_details}.+?)\s+(\w+=|$)"""
  ]
}
```