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
      """EVENT_LOCAL_TIME:\s*"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sLASTNAME:\s*"+({last_name}[^"]+)""",
      """\sFIRSTNAME:\s*"+({first_name}[^"]+)""",
      """\sEVDESCR:\s*"+({outcome}[^"]+)""",
      """\sCARDNUM:\s*"+({badge_id}\d+)""",
      """\sEMPID:\s*"+({user}[^"]+)""",
      """\sREADERDESC:\s*"+({location_full}[^"]+)"""
    ]
    DupFields = [ "location_full->location_door" ]
  }
```