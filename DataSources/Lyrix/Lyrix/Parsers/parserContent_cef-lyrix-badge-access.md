#### Parser Content
```Java
{
Name = cef-lyrix-badge-access
  Vendor = Lyrix
  Product = Lyrix
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|SKUD|""", """cs2Label=DoorName""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({outcome}[^\|]+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\Wcs3=({direction}.+?)\s+(\w+=|$)""",
    """\Wcs2=({location_door}.+?)\s+(\w+=|$)""",
    """\Wcs1=({location_building}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wsuid=({user_fullname}.+?)\s+(\w+=|$)""",
  ]
}
```