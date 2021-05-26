#### Parser Content
```Java
{
Name = s-mcafee-epo-dlp-alert-2
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """timestamp=""", """signature_id""", """is_laptop""", """Data Loss Prevention""" ]
    Fields = [
      """timestamp="{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """AutoID="{0,20}({alert_id}\d{1,100})""",
      """signature="{0,20}\s{0,100}(_|({alert_name}.+?))\s{0,100}"{0,20}
```