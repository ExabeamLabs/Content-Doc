#### Parser Content
```Java
{
Name = accessit-badge-access
  Vendor = AccessIT
  Product = Universal.NET
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy.MM.dd.HH.mm.ss"
  Conditions = [ """"globallyuniqueeventid":""", """"cardholderlink":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"globallyuniqueeventid":"({time}\d\d\d\d.\d\d.\d\d.\d\d.\d\d.\d\d)""",
    """"cardnumber":({badge_id}\d{1,100})""",
    """"accountname":"({user}[^"]{1,2000})""",
    """"cardholder":"({last_name}[^,]{1,2000}),\s({first_name}[^"]{1,2000})""",
    """"eventlocation":"({location_door}[^"]{1,2000})""",
    """"eventdescription":"({outcome}[^"]{1,2000})""",
  ]
}
```