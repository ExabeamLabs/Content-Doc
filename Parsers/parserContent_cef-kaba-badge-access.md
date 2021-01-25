#### Parser Content
```Java
{
Name = cef-kaba-badge-access
  Vendor = KABA EXOS
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
```