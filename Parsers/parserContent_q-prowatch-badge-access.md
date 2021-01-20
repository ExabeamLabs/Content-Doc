#### Parser Content
```Java
{
Name = q-prowatch-badge-access
    Vendor = ProWatch
  Product = ProWatch
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd H:mm:ss"
    Conditions = [ """ EVNT_DESCRP:""", """ LOCATION:""", """ LNAME:""", """ FNAME:""" ]
    Fields = [
      """exabeam_host=([^=]*@\s*)?({host}[^\s]+)""",
      """\sEVNT_DAT:\s*"({time}\d\d\d\d-\d\d-\d\d\s+\d{1,2}:\d\d:\d\d)""",
      """\sEVNT_DESCRP:\s*"({outcome}[^"].*?)"\s*(\w+:|$)""",
      """\sFNAME:\s*"({first_name}[^"].*?)"\s*(\w+:|$)""",
      """\sLNAME:\s*"({last_name}[^"].*?)"\s*(\w+:|$)""",
      """\sLOCATION:\s*"({location_door}[^"].*?)"\s*(\w+:|$)""",
      """\sLOOP_DESCRP:\s*"({location_building}[^"].*?)"\s*(\w+:|$)""",
      """\sCARDNO:\s*"({badge_id}[^"].*?)"\s*(\w+:|$)""",
    ]
  }
```