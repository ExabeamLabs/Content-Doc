#### Parser Content
```Java
{
Name = cef-kaspersky-security-alert-1
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF""","""|KasperskyLab|SecurityCenter|""","""cs3Label=ProductVersion""", """destinationZoneURI=""" ]
  Fields = [
    """dhost=({dest_host}[^\s]{1,2000})\s{0,100}dst=""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """cs5=({task_name}.+?)\s\w+=.+?cs5Label=TaskName""",
    """cs5=({group_name}.+?)\s\w+=.+?cs5Label=SrcAdmGroupName""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """cs2=({product_name}.+?)\s\w+=""",
    """dvchost=({host}.+?)\s\w+=""",
    """dvc=({host}.+?)\s\w+=""",
    """cs4=({alert_id}.+?)\s\w+=""",
    """CEF:\s{0,100}\d\|([^\|]{1,2000}\|){3}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|"""
    ]
}
```