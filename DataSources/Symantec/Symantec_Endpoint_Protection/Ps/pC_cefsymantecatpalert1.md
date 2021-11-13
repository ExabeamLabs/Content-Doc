#### Parser Content
```Java
{
Name = cef-symantec-atp-alert-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Symantec|""", """|atp_incident|""" ]
  Fields = [
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"user_name":"({user}[^"]{1,200})""",
    """"uuid":"({uuid}[^"]{1,2000})""",
    """({host}[\w.\-]{1,2000})\s{1,100}atp_incident:""",
    """"detection_type":"({alert_type}[^"]{1,200})""",
    """rule_name=({alert_name}[^=]{1,2000}?)\s\w{1,2000}=""",
    """description=({additional_info}[^=]{1,2000}?)\s\w{1,200}=""",
    """"atp_incident_id":({alert_id}\d{1,2000})""",
    """"incident_priority_level":"({alert_severity}[^"]{1,2000})"""
    ]



}
```