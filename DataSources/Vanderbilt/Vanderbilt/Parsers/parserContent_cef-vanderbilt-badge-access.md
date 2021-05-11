#### Parser Content
```Java
{
Name = cef-vanderbilt-badge-access
    Vendor = Vanderbilt
  Product = Vanderbilt
    Lms = ArcSight
    DataType = "physical-access"
    TimeFormat = "epoch"
    Conditions = ["""|Vanderbilt|SMS|"""]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """([^\|]*\|){5}({outcome}[^\|]+)"""
      """\Wrt=({time}\d{1,100})""",
      """\Wsuid=({user}[^\s]+)""",
      """\Wcs2=({location_building}.+?)\s{0,100}(\w+=|$)""",
      """\Wcs5=(\s{1,100}|({first_name}.+?))\s{0,100}(\w+=|$)""",
      """\Wcs4=(\s{1,100}|({last_name}.+?))\s{0,100}(\w+=|$)""",
      """\Wad.DeviceCaption=({location_door}.+?)\s{0,100}([^\s]+=|$)""",
      """\Wad.CardholderID.l=({badge_id}\d{1,100})""",
      """\Wreason=({outcome_reason}.+?)\s{0,100}(\w+=|$)"""
    ]
  }
```