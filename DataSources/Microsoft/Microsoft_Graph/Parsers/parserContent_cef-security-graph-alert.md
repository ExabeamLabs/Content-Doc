#### Parser Content
```Java
{
Name = cef-security-graph-alert
 Vendor = Microsoft
 Product = Microsoft Graph
 Lms = Directory
 DataType = "alert"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = [ """CEF:""", """|sk4-security-threat-detected|security-threat-detected|""", """dproc=Graph Security Alerts"""]
 Fields = [
   """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]+\s{1,100}Skyformation""",
   """exabeam_host=({host}[^\s]+)""",
   """"description":"({additional_info}[^\}]+?)\s{0,100}\"{1,20}
```