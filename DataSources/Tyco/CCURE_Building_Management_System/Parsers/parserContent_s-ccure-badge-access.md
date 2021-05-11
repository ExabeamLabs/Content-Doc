#### Parser Content
```Java
{
Name = s-ccure-badge-access
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """MessageType="Card""", """SecondaryObjectName="""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"\s{1,100}(\w+=|$)""",
    """,\s{0,100}ServerName="({host}[^"]+)""",
    """,\s{0,100}MessageType="({outcome}[^"]+)""",
    """,\s{0,100}Name="({user_fullname}[^"]+)"""",
    """,\s{0,100}Name="({last_name}[^",]+)\s{0,100}
```