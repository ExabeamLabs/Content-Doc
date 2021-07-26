#### Parser Content
```Java
{
Name = json-bluecoat-proxy-web-activity
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance 
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """filter_result_CF""", """action_CF""", """BlueCoat_CL""" ]
  Fields = [
    """"TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})"{1,20}
```