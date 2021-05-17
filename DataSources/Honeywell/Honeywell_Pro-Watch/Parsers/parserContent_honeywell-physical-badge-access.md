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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"fielddatetime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"source":"({src_host}[\w\-.]{1,2000})""",
    """"category":({category}\d{1,100})""",
    """"eventid":({event_code}\d{1,100})""",
    """"cardholderid":({badge_id}\d{1,100})""",
    """"areacode":({area_code}\d{1,100})""",
    """"description":"({additional_info}[^"]{1,2000})""",
    """"accessreason":"({outcome}[^"]{1,2000})""",
    """"locationfullname":"({location_full}[^"]{1,2000})""",
    """"areaname":"({location_area}[^"]{1,2000})""",
    """"cardnumber":"({card_num}[^"]{1,2000})""",
    """"cardholderfirstname":"({first_name}[^"]{1,2000})""",
    """"cardholderlastname":"({last_name}[^"]{1,2000})""",
    """"zoneentered":"({location_door}[^"]{1,2000})""",
  ]
  DupFields = [ "location_area->location_building" ]
}
```