#### Parser Content
```Java
{
Name = cef-cybereason-security-alert
  Vendor = Cybereason
  Product = Cybereason
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =Cybereason""", """"username":""", """"name":""", """dproc=Malops""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"detectionType":\{[^=]{1,2000}?"values":\["({alert_type}[^"]{1,2000})"""",
    """"Machine"[^\]]{1,2000}"name":"({dest_host}[^"]{1,2000})"""",
    """"User"[^\]]{1,2000}"name":"(({domain}[^\\]{1,2000})?[\\]{1,2000})?(system|({user}[^"]{1,2000})?)?""",
    """"creationTime":\{[^]}]{1,2000}?"values":\["({time}\d{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})"""",
    """"elementDisplayName":[^\]]{1,2000}"values":\["({alert_name}[^"]{1,2000})"""",
    """"malopActivityTypes":\{"[^]}]{1,2000}?"values":\["({threat_category}[^"]{1,2000})"""",
  ]


}
```