#### Parser Content
```Java
{
Name = s-mcafee-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "_timestamp=", "signature_id", "threat_handled", "is_laptop" ]
    Fields = [
      """detected_timestamp="{0,20}\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """AutoID="{0,20}({alert_id}\d{1,100})""",
      """event_id="{0,20}({alert_id}\d{1,100})""",
      """signature="{0,20}\s{0,100}(_|({alert_name}.+?))\s{0,100}"{0,20}
```