#### Parser Content
```Java
{
Name = syslog-physical-badge-access-1
    Vendor = Lenel
    Product = OnGuard
    Lms = Syslog
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = ["""LOG_TIME_UTC=""","""EVENT_TIME_CT=""", """EVDESCR=""", """READERDESC=""", """MACHINE_NAME=""", """BUILDING_CODE="""]
    Fields = [
      """LOG_TIME_UTC=\\?"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """LOG_HOST=\\?"({host}[^\\"]{1,2000})""",
      """CARDNUM="{0,20}({badge_id}[^=]{1,2000})\s\w{1,2000}=""",
      """USER=\\?"({user}[^\\"]{1,200})""",
      """EVDESCR=\\?"({outcome}[^\\"]{1,2000})""",
      """LASTNAME=\\?"({last_name}[^\\"]{1,2000})""",
      """FIRSTNAME=\\?"({first_name}[^\\"]{0,2000}?)\s{0,100}\\""",
      """READERDESC=\\?"({location_door}[^\\"]{1,2000})""",
      """CITY_CODE=\\?"({location_city}[^\\"]{1,2000})""",
      """BUILDING_CODE=\\?"({location_building}[^\\"]{1,2000})"""
    ]
  

}
```