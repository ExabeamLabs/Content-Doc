#### Parser Content
```Java
{
Name = lenel-badge-access-3
  Vendor = Lenel
  Product = OnGuard
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """ EVENT_TIME_UTC=""", """"Access Granted"""", """EVTDESCR=""", """READERDESC=""" ]
  Fields = [
    """EVTDESCR="{0,10}({outcome}[^"]{1,2000})"{0,10}""",
    """EVENT_TIME_UTC="{0,10}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{1,100})"{0,10}""",
    """FIRSTNAME="{0,10}({first_name}[^"]{1,2000})"{0,10}""",
    """LASTNAME="{0,10}({last_name}[^"]{1,2000})"{0,10}""",
    """CARDNUM="{0,10}({badge_id}\d{1,100})"{0,10}""",
    """EMPID="{0,10}({employee_id}[^"]\d{1,2000})"{0,10}""",
    """\sNAME="{0,10}({location_building}[^"]{1,2000})"{0,10}""",
    """READERDESC="{0,10}({location_door}[^"]{1,2000})"{0,10}""",
    """SERIALNUM="{0,10}({serial_num}[^"]{1,2000})"{0,10}"""
  ]


}
```