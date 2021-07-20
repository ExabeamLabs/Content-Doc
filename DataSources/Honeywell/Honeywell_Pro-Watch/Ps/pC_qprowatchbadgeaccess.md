#### Parser Content
```Java
{
Name = q-prowatch-badge-access
    Vendor = Honeywell
  Product = Honeywell Pro-Watch
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd H:mm:ss"
    Conditions = [ """ EVNT_DESCRP:""", """ LOCATION:""", """ LNAME:""", """ FNAME:""" ]
    Fields = [
      """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """\sEVNT_DAT:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d{1,2}:\d\d:\d\d)""",
      """\sEVNT_DESCRP:\s{0,100}"({outcome}[^"].*?)"\s{0,100}(\w+:|$)""",
      """\sFNAME:\s{0,100}"({first_name}[^"].*?)"\s{0,100}(\w+:|$)""",
      """\sLNAME:\s{0,100}"({last_name}[^"].*?)"\s{0,100}(\w+:|$)""",
      """\sLOCATION:\s{0,100}"({location_door}[^"].*?)"\s{0,100}(\w+:|$)""",
      """\sLOOP_DESCRP:\s{0,100}"({location_building}[^"].*?)"\s{0,100}(\w+:|$)""",
      """\sCARDNO:\s{0,100}"({badge_id}[^"].*?)"\s{0,100}(\w+:|$)""",
    ]
  }
```