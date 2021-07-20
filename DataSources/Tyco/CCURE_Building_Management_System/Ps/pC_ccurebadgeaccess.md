#### Parser Content
```Java
{
Name = ccure-badge-access
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"messagetype":"Card""", """"statecode":"""", """"primaryobjectname":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"messageutc":"({time}[^"]{1,2000})""",
    """"statecode":"({event_name}[^"]{1,2000})""",
    """"messagetype":"({outcome}[^"]{1,2000})""",
    """"primaryobjectname":"{0,20}(null|({last_name}[^",]{1,2000}?)\s{0,100}
```