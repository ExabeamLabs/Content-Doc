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
    """Date_tiem\s{0,100}=\s{0,100}({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """LAN_ID\s{0,100}=\s{0,100}({user}[^\s,]{1,2000})""",
    """READER_NAME\s{0,100}=\s{0,100}({location_door}[^,]{1,2000})""",
    """OFFICE\s{0,100}=\s{0,100}({location_building}.+?)\s{1,100}({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?, ([\w\s]{1,2000}=|$)""",
    """Access_Info\s{0,100}=\s{0,100}({outcome}[^,]{1,2000}?)[\s,]{0,2000}([\w\s]{1,2000}=|$)""",
  ]
}
```