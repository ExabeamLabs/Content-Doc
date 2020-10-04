#### Parser Content
```Java
{
Name = cef-kaba-badge-access
  Vendor = KABA EXOS
  Product = KABA EXOS
  Lms = ArcSight
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """|KABA|EXOS 9300|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)"""
    """\Wrt=({time}\d+)""",
    """\Wduser=({user}[^\s]+)""",
    """\Wmsg=({location_door}.+?)\s*(\w+=|$)""",
    """\Wcs2=({badge_id}\d+)"""
  ]
}

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