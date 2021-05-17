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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^\|]{0,2000}\|){5}({outcome}[^\|]{1,2000})"""
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user}[^\s]{1,2000})""",
    """\Wmsg=({location_door}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs2=({badge_id}\d{1,100})"""
  ]
}
```