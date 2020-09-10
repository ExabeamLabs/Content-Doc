#### Parser Content
```Java
{
Name = prowatch-badge-access
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"evnt_dat":"""", """"evnt_descrp":"""", """"badge_employeeid":"""", """"cardstatus_descrp":"""" ]
}

${ProWatchParserTemplates.prowatch-badge-access}{
  Name = prowatch-badge-access-1
  Conditions = [ """"BADGENO":""", """"EVNT_DESCRP":""", """"LOCATION":""" ]
}

  {
    Name = timelox-badge-access
    Vendor = TimeLox
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"eventtime":"""", """"doorgroupname":"""", """"issued by":""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """"doorgroupname":"({door_group_name}[^"]+)""",
      """"eventtime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """"registration no\.":({registration_no}\d+)""",
      """"userid":"({user_id}[^"]+)""",
      """"event":"({outcome}[^"]+)""",
      """"issued by":"(n\/a|({user}[^"]+))""",
      """"door":"({location_door}[^"]+)""",
      """"blockinggroupname":"(n\/a|({blockinggroupname}[^"]+))""",
      """"@version":"({version}[^"]+)""",
      """"user group":"({user_group}[^"]+)"""
    ]
  }
```