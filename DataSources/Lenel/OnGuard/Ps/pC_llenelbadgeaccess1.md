#### Parser Content
```Java
{
Name = l-lenel-badge-access-1
  Conditions = [ """"EVTDESCR":"Access Denied"""", """"BADGENAME":""", """"EMPID":""", """"CARDNUM":""", """leaf""" ]

lenel-physical-access = {
    Vendor = Lenel
    Product = OnGuard
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
    Fields = [
       """"CARDNUM":\s{0,100}({badge_id}\d{1,100})""",
       """"FIRSTNAME":\s{0,100}"({first_name}[^"]{1,2000}?)\s{0,100}"""",
       """"Hostname":\s{0,100}"({host}[^"]{1,2000})""",
       """"LASTNAME":\s{0,100}"({last_name}[^"]{1,2000}?)\s{0,100}"""",
       """"READERDESC":\s{0,100}"({location_door}[^"]{1,2000})""",
       """"EVTDESCR":\s{0,100}"({outcome}[^"]{1,2000})""",
       """"EVENT_TIME_UTC":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6})""",
       """"EMPID":\s{0,100}"({employee_id}[^"]{1,2000}?)\s{0,100}""""
    ]
    DupFields = [ "location_door->location_full" 
}
```