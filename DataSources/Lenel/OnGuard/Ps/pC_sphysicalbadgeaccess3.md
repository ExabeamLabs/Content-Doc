#### Parser Content
```Java
{
Name = s-physical-badge-access-3
    Vendor = Lenel
    Product = OnGuard
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["EVDESCR=","exabeam_raw"]
    Fields = [
      """exabeam_raw="{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EVENT_TIME_UTC="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """EMPID="{0,20}({employee_id}[^,"]{0,2000})""",
      """CARDNUM="{0,20}({badge_id}[^,"]{0,2000})""",
      """UserID="({user}[^"]{0,2000})""",
      """EVDESCR="({outcome}[^"]{0,2000})""",
      """LASTNAME="({last_name}[^"]{0,2000})""",
      """FIRSTNAME="({first_name}[^"]{0,2000})""",
      """READERDESC="({location_door}[^"]{0,2000})""",
      """, NAME="({location_building}[^"]{0,2000})""",
      """, NAME="({location_city}[^\s-]{0,2000})""",
      """location="({location_city}[^. ]{0,2000})""",
      """location="({location_door}[^"]{0,2000})""",
      """location="({location_building}[A-Z]{1,2000}\s[A-Z]{1,2000})""",
      """location="({location_building}[\w\s-]{1,2000}\.-?\d)"""
    ]
  }
```