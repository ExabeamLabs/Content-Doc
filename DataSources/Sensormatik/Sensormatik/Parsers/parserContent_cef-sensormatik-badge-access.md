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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)"""
    """\Wrt=({time}\d+)""",
    """\Wsuser=({last_name}[^,]+), ({first_name}[^\s]+)\s(\d+|\w+=)""",
    """\Wcs3=({location_door}.+?)\s*(\w+=|$)""",
    """\Wcs2=({direction}.+?)\s*(\w+=|$)"""
  ]
}
```