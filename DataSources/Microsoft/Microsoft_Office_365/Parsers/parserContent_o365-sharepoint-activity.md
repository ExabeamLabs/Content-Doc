#### Parser Content
```Java
{
Name = o365-sharepoint-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """SharePoint""", """ItemType""" ]
  Fields = [
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]+)""",
    """exabeam_host=({host}[^\s]+)""",
    """"host\\*"{1,20}:\\*\s{0,100}"{1,20}({host}[^"\\]+)""",
    """"SourceRelativeUrl\\*"{1,20}:\\*\s{0,100}"{1,20}({file_parent}[^"]+)""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}({file_path}[^"]+)[\\"](?!\\u\d{1,100})""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}({file_parent}[^"]+)[\\\/](?!u\d{1,100})""",
    """"ObjectId\\*"{1,20}:\\*\s{0,100}"{1,20}[^"]*?({file_name}[^\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)"(?!u\d{1,100})""",
    """"Operation\\*"{1,20}:\\*\s{0,100}"{1,20}({accesses}[^"\\]+)""",
    """"UserId\\*"{1,20}:\\*\s{0,100}"{1,20}({user_email}[^"@]+@({email_domain}[^@"\\]+))""",
    """"UserId\\*"{1,20}:\\*\s{0,100}"{1,20}(Teams Meeting Anonymous Participant|(({domain}[^\\\s@"]+)\\+)?({user}[^\\\s@"]+)\s)""",
    """"ClientIP\\*"{1,20}:\\*\s{0,100}"{1,20}({src_ip}[a-fA-F:\d.]+)""",
    """"UserAgent\\*"{1,20}:\\*\s{0,100}"{1,20}({user_agent}[^"\\]+)"{1,20}
```