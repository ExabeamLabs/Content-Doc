#### Parser Content
```Java
{
Name = o365-onedrive-app-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","OneDrive","20""", ""","SharePoint",""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    ""","({app}OneDrive)","\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z"(,("[^"]*"|[^,]*)){2}
```