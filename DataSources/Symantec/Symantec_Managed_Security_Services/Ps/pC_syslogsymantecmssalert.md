#### Parser Content
```Java
{
Name = syslog-symantec-mss-alert
  Vendor = Symantec
  Product = Symantec Managed Security Services
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Symantec MSS alert Conditions>""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_raw=(?:"|')?\s{0,100}({alert_id}\d{1,100})\s{0,100}(?:"|')?,""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100}
```