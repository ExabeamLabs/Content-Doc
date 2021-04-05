#### Parser Content
```Java
{
Name = q-lenel-badge-access-1
  Vendor = Lenel
  Product = Lenel OnGuard
  Lms = QRadar
  DataType = "physical-access"
  TimeFormat =  "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ EVDESCR: """", """ USERID: """", """ PANELNAME: """", """ READERDESC: """" ]
  Fields = [
    """EVENT_TIME_UTC:\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\sLASTNAME:\s*"({last_name}[^"]+)""",
    """FIRSTNAME:\s*"({first_name}[^"]+)""",
    """\sEVDESCR:\s*"({outcome}[^"]+)""",
    """\sUSERID:\s*"({badge_id}[^"]+)""",
    """\sREADERDESC:\s*"({location_door}[^"]+)""",
    """PANELNAME:\s*"({location_building}[^"]+)"""
  ]
}
```