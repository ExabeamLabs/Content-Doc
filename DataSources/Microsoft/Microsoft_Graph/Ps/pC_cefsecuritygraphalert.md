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
   """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]{1,2000}\s{1,100}Skyformation""",
   """exabeam_host=({host}[^\s]{1,2000})""",
   """"description":"({additional_info}[^\}]{1,2000}?)\s{0,100}\"{1,20

}
```