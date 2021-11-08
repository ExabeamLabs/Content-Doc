#### Parser Content
```Java
{
Name = fireeye-mps-xml-extended-head-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """.1.alert:""","""msg="extended"""","""product="Web MPS""" ]
  Fields = [
    """<occurred>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}\S+)""",
    """<alert id="({alert_id}[^"]{1,2000})""",
    """<malware name="({alert_name}[^"]{1,2000})"""",
    """xsi:schemaLocation=.+?name="({alert_type}[^"]{1,2000})".*severity="({alert_severity}[^"]{1,2000})""""
  ]
}
```