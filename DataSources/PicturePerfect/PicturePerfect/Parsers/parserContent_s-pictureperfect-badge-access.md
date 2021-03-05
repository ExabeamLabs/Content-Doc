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
      """exabeam_host=({host}[\w.\-]+)""",
      """^[^|]*?\|([^|]*\|){2}({user}[^|]+)\|""",
      """^[^|]*?\|([^|]*\|){3}({first_name}[^|]+)\|""",
      """^[^|]*?\|([^|]*\|){4}({last_name}[^|]+)\|""",
      """^[^|]*?\|([^|]*\|){12}({location_full}[^|]+)\|""",
      """^[^|]*?\|([^|]*\|){12}[^|]*\s({direction}(?:IN|OUT))\s[^|]*\|""",
      """^[^|]*?\|([^|]*\|){15}({time}\d{8}\|\d{6})\|"""
    ]
    DupFields = [ "location_full->location_door" ]
  }
```