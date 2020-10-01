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
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """([^\|]*\|){5}({outcome}[^\|]+)"""
      """\Wrt=({time}\d+)""",
      """\Wsuid=({user}[^\s]+)""",
      """\Wcs2=({location_building}.+?)\s*(\w+=|$)""",
      """\Wcs5=(\s+|({first_name}.+?))\s*(\w+=|$)""",
      """\Wcs4=(\s+|({last_name}.+?))\s*(\w+=|$)""",
      """\Wad.DeviceCaption=({location_door}.+?)\s*([^\s]+=|$)""",
      """\Wad.CardholderID.l=({badge_id}\d+)""",
      """\Wreason=({outcome_reason}.+?)\s*(\w+=|$)"""
    ]
  }
```