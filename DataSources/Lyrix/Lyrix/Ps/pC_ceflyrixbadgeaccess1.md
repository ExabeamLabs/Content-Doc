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
    """\Wact=({outcome}.+?)\s{1,100}\w+=""",
    """\Wcs1=({badge_id}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({location_door}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs3=({location_building}.+?)\s{1,100}(\w+=|$)""",
    """ flexString1=({location_city}.+?)\s{1,100}\S+=""",
    """ flexString2=({additional_info}.+?)\s{1,100}\S+="""
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)"""
  ]
  DupFields=[ "user->user_fullname" ]
}
```