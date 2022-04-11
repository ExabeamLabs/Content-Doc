#### Parser Content
```Java
{
Name = duo-app-activity-1
  Conditions = [ """"action":"user_update"""", """"event-name":"user-updated"""", """app-username""", """"src-application-name":"DUO"""" ]

duo-app-activity-1 = {
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"event-name":"({event_name}[^"]{1,2000})"""",
    """"action":"({activity}[^"]{1,2000})"""",
    """"username":"(({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^"]{1,2000}))|({user}[^"]{1,2000}))"""",
    """"object":"({object}[^"]{1,2000})"""",
    """"src-application-name":"({app}[^"]{1,2000})"""",
  
}
```