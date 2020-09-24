#### Parser Content
```Java
{
Name = cef-lyrix-badge-access-1
  Vendor = Lyrix
  Product = Lyrix
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Lyrix|""", """|SKUD""", """cs3Label=DEPARTMENT""" ]
  Fields = [
    """\Wact=({outcome}.+?)\s+\w+=""",
    """\Wcs1=({badge_id}.+?)\s+(\w+=|$)""",
    """\Wcs6=({location_door}.+?)\s+(\w+=|$)""",
    """\Wcs3=({location_building}.+?)\s+(\w+=|$)""",
    """ flexString1=({location_city}.+?)\s+\S+=""",
    """ flexString2=({additional_info}.+?)\s+\S+="""
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wrt=({time}\d+)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)"""
  ]
  DupFields=[ "user->user_fullname" ]
}
```