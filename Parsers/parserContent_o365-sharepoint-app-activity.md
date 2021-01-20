#### Parser Content
```Java
{
Name = o365-sharepoint-app-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","SharePoint","20""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    ""","({app}SharePoint)","\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z"(,("[^"]*"|[^,]*)){2}
```