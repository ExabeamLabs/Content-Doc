#### Parser Content
```Java
{
Name = o365-sharepoint-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """SharePoint""", """ItemType""" ]
  Fields = [
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """"host\\*"{1,20}:\\*\s{0,100}"{1,20}(::ffff:)?({host}[^"\\]{1,2000})""",
    """"SourceRelativeUrl\\*"{1,20}:\\*\s{0,100}"{1,20}({file_parent}[^"]{1,2000})""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}({file_path}[^"]{1,2000})[\\"](?!\\u\d{1,100})""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}({file_parent}[^"]{1,2000})[\\\/](?!u\d{1,100})""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}[^"]{0,2000}?({file_name}[^\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)"(?!u\d{1,100})""",
    """"Operation\\*"{1,20}:\\*\s{0,100}"{1,20}({activity}[^"\\]{1,2000})""",
    """"UserId\\*"{1,20}:\\*\s{0,100}"{1,20}({user_email}[^"@]{1,2000}@({email_domain}[^@"\\\.]{1,2000}\.[^"]{1,2000}))"""",
    """"ClientIP\\*"{1,20}:\\*\s{0,100}"{1,20}({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"UserAgent\\*"{1,20}:\\*\s{0,100}"{1,20}({user_agent}[^"\\]{1,2000})"{1,20

}
```