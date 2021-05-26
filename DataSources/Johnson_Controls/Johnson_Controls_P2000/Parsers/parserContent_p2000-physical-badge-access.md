#### Parser Content
```Java
{
Name = p2000-physical-badge-access
  Vendor = Johnson Controls
  Product = Johnson Controls P2000
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"x_badge_number"""", """"x_fac_code"""", """"x_timed_overrd"""", """"x_cardholder_guid"""", """"x_cardholder_nick_name"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"x_timestamp":"({time}[^"]{1,2000}?)Z?"""",
    """"x_badge_number":"({badge_id}[^"]{1,2000}?)\s{0,100}"""",
    """"x_fname":"({first_name}[^"]{1,2000}?)\s{0,100}"""",
    """"x_lname":"({last_name}[^"]{1,2000}?)\s{0,100}"""",
    """"x_event_name":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"x_panel_name":"({location_building}[^"]{1,2000}?)\s{0,100}"""",
    """"x_term_name":"({location_door}[^"]{1,2000}?)\s{0,100}"""",
    """"x_item_name":"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"site":"({location_city}[^"]{1,2000}?)\s{0,100}"""",
  ]
}
```