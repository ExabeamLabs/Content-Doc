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
    """CEF:([^\|]{0,2000}\|){5}({outcome}[^\|]{1,2000})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wcs3=({direction}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=({location_door}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=({location_building}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\Wsuid=({user_fullname}.+?)\s{1,100}(\w+=|$)"""
  ]
}
```