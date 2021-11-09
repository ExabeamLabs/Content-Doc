#### Parser Content
```Java
{
Name = prowatch-badge-access-1
  Product = Honeywell Pro-Watch
  Conditions = [ """"BADGENO":""", """"EVNT_DESCRP":""", """"LOCATION":""" ]
}
prowatch-badge-access = {
  Vendor = Honeywell
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """:f+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}\{""",
    """"((?i)location)":\s{0,100}"\s{0,100}({location_building}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)descrp)":\s{0,100}"\s{0,100}({location_door}[^"]{1,2000}?)\s{0,100}"""",
    """"evnt_dat":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"EVNT_DAT":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"BADGENO":\s{0,100}"({badge_id}[^"]{1,2000})""",
    """"((?i)cardno)":\s{0,100}"({badge_id}\d{1,100})""",
    """"((?i)comp_name)":\s{0,100}"\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)evnt_descrp)":\s{0,100}"\s{0,100}({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)threat_lev)":({threat_level}\d{1,100})""",
    """"((?i)fname)":"\s{0,100}({first_name}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)lname)":"\s{0,100}({last_name}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)badge_employeeid)":"\s{0,100}({employee_id}[^"]{1,2000}?)\s{0,100}"""",
    """"((?i)cardstatus_descrp)":"\s{0,100}({card_status}[^"]{1,2000}?)\s{0,100}""""
  ]}
```