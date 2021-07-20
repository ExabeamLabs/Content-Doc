#### Parser Content
```Java
{
Name = cef-sensormatik-badge-access
  Vendor = Sensormatik
  Product = Sensormatik
  Lms = ArcSight
  DataType = "physical-access"
  TimeFormat = "epoch"
  Conditions = [ """|Sensormatik|""", """suser=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^\|]{0,2000}\|){5}({outcome}[^\|]{1,2000})"""
    """\Wrt=({time}\d{1,100})""",
    """\Wsuser=({last_name}[^,]{1,2000}), ({first_name}[^\s]{1,2000})\s(\d{1,100}|\w+=)""",
    """\Wcs3=({location_door}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs2=({direction}.+?)\s{0,100}(\w+=|$)"""
  ]
}
```