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
      """exabeam_host=({host}[^\s]+)""",
      """"severity"+:"+({alert_severity}[^"]+)"""",
      """cat=({alert_type}[^\s]+)\s""",
      """destinationServiceName=({service}.+?)\s*\w+=""",
      """dpriv=({alert_type}.+?)\s*\w+=""",
      """dproc=(N\/A|({process_name}.+?))\s*\w+=""",
      """msg=({alert_name}.+?)\s*\w+=""",
      """requestContext=({target}.+?)\s*\w+=""",
      """requestClientApplication=({app}.+?)\s*\w+=""",
      """"headerTo":\[({recipients}[^\]]+)\],""",
      """"headerTo":\["({recipient}[^"]+)"""",
      """"subject":"({subject}[^"]+)",""",
      """"messageSize":({bytes}\d+)""",
    ]
    DupFields = [ "recipient->external_address" ]
  }
```