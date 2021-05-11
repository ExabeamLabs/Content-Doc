#### Parser Content
```Java
{
Name = honeywell-physical-badge-access
  Vendor = Honeywell
  Product = Honeywell Pro-Watch
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"fielddatetime":"""", """"areaname":"""", """"cardholderid":""", """"locationfullname":"""", """"cardholderfirstname":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"fielddatetime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"source":"({src_host}[\w\-.]+)""",
    """"category":({category}\d{1,100})""",
    """"eventid":({event_code}\d{1,100})""",
    """"cardholderid":({badge_id}\d{1,100})""",
    """"areacode":({area_code}\d{1,100})""",
    """"description":"({additional_info}[^"]+)""",
    """"accessreason":"({outcome}[^"]+)""",
    """"locationfullname":"({location_full}[^"]+)""",
    """"areaname":"({location_area}[^"]+)""",
    """"cardnumber":"({card_num}[^"]+)""",
    """"cardholderfirstname":"({first_name}[^"]+)""",
    """"cardholderlastname":"({last_name}[^"]+)""",
    """"zoneentered":"({location_door}[^"]+)""",
  ]
  DupFields = [ "location_area->location_building" ]
}
```