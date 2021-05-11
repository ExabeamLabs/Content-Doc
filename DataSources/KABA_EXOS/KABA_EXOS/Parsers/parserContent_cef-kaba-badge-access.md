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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)"""
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user}[^\s]+)""",
    """\Wmsg=({location_door}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs2=({badge_id}\d{1,100})"""
  ]
}
```