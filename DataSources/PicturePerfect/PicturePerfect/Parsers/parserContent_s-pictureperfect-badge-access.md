#### Parser Content
```Java
{
Name = s-pictureperfect-badge-access
    Vendor = PicturePerfect
  Product = PicturePerfect
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat =  "yyyyMMdd|HHmmss"
    Conditions = [ """pictureperfect""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){2}({user}[^|]{1,2000})\|""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){3}({first_name}[^|]{1,2000})\|""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){4}({last_name}[^|]{1,2000})\|""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){12}({location_full}[^|]{1,2000})\|""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){12}[^|]{0,2000}\s({direction}(?:IN|OUT))\s[^|]{0,2000}\|""",
      """^[^|]{0,2000}?\|([^|]{0,2000}\|){15}({time}\d{8}\|\d{6})\|"""
    ]
    DupFields = [ "location_full->location_door" ]
  }
```