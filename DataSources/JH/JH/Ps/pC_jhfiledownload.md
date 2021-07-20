#### Parser Content
```Java
{
Name = jh-file-download
  Vendor = JH
  Product = JH
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Download complete", "download_time:" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """login:\s{0,100}"{0,20}({user}[^@"]{1,2000})""",
    """login:\s{0,100}"{0,20}({user_email}[^"@]{1,2000}@[^"]{1,2000})""",
    """ordernum:\s{0,100}"{0,20}({order_num}\d{1,100})""",
    """s_date:\s{0,100}"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """flag:\s{0,100}"{0,20}({accesses}[^"]{1,2000})""",
    """ip_address:\s{0,100}"{0,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """contact_id:\s{0,100}"{0,20}({contact_id}(-)?\d{1,100})""",
    """source:\s{0,100}"{0,20}({download_source}[^"]{1,2000})""",
  ]
  DupFields = [ "accesses->activity" ]
}
```