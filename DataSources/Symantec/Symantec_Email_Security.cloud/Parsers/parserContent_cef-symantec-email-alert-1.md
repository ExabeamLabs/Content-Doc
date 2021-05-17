#### Parser Content
```Java
{
Name = cef-symantec-email-alert-1
    Vendor = Symantec
    Product = Symantec Email Security.cloud
    Lms = ArcSight
    DataType = "security-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """destinationServiceName=Symantec Email Security.cloud""", """CEF""", """|security-threat-detected|"""]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"severity"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})"""",
      """cat=({alert_type}[^\s]{1,2000})\s""",
      """destinationServiceName=({service}.+?)\s{0,100}\w+=""",
      """dpriv=({alert_type}.+?)\s{0,100}\w+=""",
      """dproc=(N\/A|({process_name}.+?))\s{0,100}\w+=""",
      """msg=({alert_name}.+?)\s{0,100}\w+=""",
      """requestContext=({target}.+?)\s{0,100}\w+=""",
      """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
      """"headerTo":\[({recipients}[^\]]{1,2000})\],""",
      """"headerTo":\["({recipient}[^"]{1,2000})"""",
      """"subject":"({subject}[^"]{1,2000})",""",
      """"messageSize":({bytes}\d{1,100})""",
    ]
    DupFields = [ "recipient->external_address" ]
  }
```