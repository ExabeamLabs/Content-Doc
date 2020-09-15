#### Parser Content
```Java
{
Name = s-prowatch-badge-access
  Product = Honeywell Pro-Watch
  Conditions = [ """REFID_TYP=""", """EVNT_DESCRP=""", """BADGENO="""" ]
}

${ProWatchParserTemplates.s-prowatch-badge-access}{
  Name = s-prowatch-badge-access-2
  Product = Honeywell Pro-Watch
  Conditions = [ """REFID_TYP=""", """EVNT_DESCRP=""", """CARDNO="""" ]
}

  {
    Name = q-prowatch-badge-access
    Vendor = Honeywell
  Product = Honeywell Pro-Watch
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