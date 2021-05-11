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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)"""
    """\Wrt=({time}\d{1,100})""",
    """\Wsuser=({last_name}[^,]+), ({first_name}[^\s]+)\s(\d{1,100}|\w+=)""",
    """\Wcs3=({location_door}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs2=({direction}.+?)\s{0,100}(\w+=|$)"""
  ]
}
```