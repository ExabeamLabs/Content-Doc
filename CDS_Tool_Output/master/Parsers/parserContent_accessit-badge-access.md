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
    """exabeam_host=({host}[\w.\-]+)""",
    """"globallyuniqueeventid":"({time}\d\d\d\d.\d\d.\d\d.\d\d.\d\d.\d\d)""",
    """"cardnumber":({badge_id}\d+)""",
    """"accountname":"({user}[^"]+)""",
    """"cardholder":"({last_name}[^,]+),\s({first_name}[^"]+)""",
    """"eventlocation":"({location_door}[^"]+)""",
    """"eventdescription":"({outcome}[^"]+)""",
  ]
}
```