#### Parser Content
```Java
{
Name = galaxy-physical-badge-access
  Vendor = Galaxy
  Product = Galaxy
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """, LAN_ID = """,""", READER_NAME = """, """, Access_Info = """ ]
  Fields = [
    """Date_tiem\s*=\s*({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """LAN_ID\s*=\s*({user}[^\s,]+)""",
    """READER_NAME\s*=\s*({location_door}[^,]+)""",
    """OFFICE\s*=\s*({location_building}.+?)\s+({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?, ([\w\s]+=|$)""",
    """Access_Info\s*=\s*({outcome}[^,]+?)[\s,]*([\w\s]+=|$)""",
  ]
}
```