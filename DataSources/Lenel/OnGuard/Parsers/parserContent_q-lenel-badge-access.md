#### Parser Content
```Java
{
Name = q-lenel-badge-access
    Vendor = Lenel
    Product = OnGuard
    Lms = QRadar
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ EVDESCR: ""Access Granted"" """, """"" EMPID: """"" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """EVENT_LOCAL_TIME:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sLASTNAME:\s{0,100}"{1,20}({last_name}[^"]+)""",
      """\sFIRSTNAME:\s{0,100}"{1,20}({first_name}[^"]+)""",
      """\sEVDESCR:\s{0,100}"{1,20}({outcome}[^"]+)""",
      """\sCARDNUM:\s{0,100}"{1,20}({badge_id}\d{1,100})""",
      """\sEMPID:\s{0,100}"{1,20}({user}[^"]+)""",
      """\sREADERDESC:\s{0,100}"{1,20}({location_full}[^"]+)"""
    ]
    DupFields = [ "location_full->location_door" ]
  }
```