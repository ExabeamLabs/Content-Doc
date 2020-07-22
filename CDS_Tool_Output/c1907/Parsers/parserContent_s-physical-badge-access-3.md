#### Parser Content
```Java
{
Name = s-physical-badge-access-3
    Vendor = Lenel
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["EVDESCR=","exabeam_raw"]
    Fields = [
      """exabeam_raw="+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EVENT_TIME_UTC="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """EMPID="*({employee_id}[^,"]*)""",
      """CARDNUM="*({badge_id}[^,"]*)""",
      """UserID="({user}[^"]*)""",
      """EVDESCR="({outcome}[^"]*)""",
      """LASTNAME="({last_name}[^"]*)""",
      """FIRSTNAME="({first_name}[^"]*)""",
      """READERDESC="({location_door}[^"]*)""",
      """, NAME="({location_building}[^"]*)""",
      """, NAME="({location_city}[^\s-]*)""",
      """location="({location_city}[^. ]*)""",
      """location="({location_door}[^"]*)""",
      """location="({location_building}[A-Z]+\s[A-Z]+)""",
      """location="({location_building}[\w\s-]+\.-?\d)"""
    ]
  }
```