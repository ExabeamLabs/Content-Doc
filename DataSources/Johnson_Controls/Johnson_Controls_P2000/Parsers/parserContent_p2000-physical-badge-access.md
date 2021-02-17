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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"x_timestamp":"({time}[^"]+?)Z?"""",
    """"x_badge_number":"({badge_id}[^"]+?)\s*"""",
    """"x_fname":"({first_name}[^"]+?)\s*"""",
    """"x_lname":"({last_name}[^"]+?)\s*"""",
    """"x_event_name":"({event_name}[^"]+?)\s*"""",
    """"x_panel_name":"({location_building}[^"]+?)\s*"""",
    """"x_term_name":"({location_door}[^"]+?)\s*"""",
    """"x_item_name":"({additional_info}[^"]+?)\s*"""",
    """"site":"({location_city}[^"]+?)\s*"""",
  ]
}
```