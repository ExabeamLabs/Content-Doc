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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"messageutc":"({time}[^"]+)""",
    """"statecode":"({event_name}[^"]+)""",
    """"messagetype":"({outcome}[^"]+)""",
    """"primaryobjectname":"{0,20}(null|({last_name}[^",]+?)\s{0,100}
```