#### Parser Content
```Java
{
Name = exa-app-activity-4
  DataType = "app-activity"
  Conditions = [ """"Exabeam Audit Event"""", """"event_type":"app-activity"""", """"activity":"Threat hunter search""" ]

exa-events = {
  Vendor = Exabeam
  Product = Exabeam Advanced Analytics
  Lms = Exabeam
  TimeFormat = "epoch"
  Fields = [
    """"time":({time}\d{1,100})""",
    """"host":"({host}[^"]{1,2000})""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"user":"((\[saml\])?({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"\s]{1,2000}))"""",
    """"activity":"({activity}[^"]{1,2000})""",
    """"additional_info":"({additional_info}.+?),?\s{0,100}"\}\}""",
    """"app":"({app}[^"]{1,2000})""",
  
}
```