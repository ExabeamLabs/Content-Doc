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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\scs4=({user}.+?)\s{1,100}(\w+=|$)""",
    """({activity}File Copy)""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=({file_name}.+?(\.({file_ext}[^.\s]+))?)\s{1,100}(\w+=|$)""",
    """\sfilePath=({file_parent}.+?)\s{1,100}(\w+=|$)""",
    """\sflexString2=({device_type}.+?)\s{1,100}(\w+=|$)""",
    """\sflexString1=({action}.+?)\s{1,100}(\w+=|$)""",
    """\scs5=({activity_details}.+?)\s{1,100}(\w+=|$)"""
  ]
}
```