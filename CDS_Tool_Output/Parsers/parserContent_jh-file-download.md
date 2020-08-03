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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """login:\s*"*({user}[^@"]+)""",
    """login:\s*"*({user_email}[^"@]+@[^"]+)""",
    """ordernum:\s*"*({order_num}\d+)""",
    """s_date:\s*"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """flag:\s*"*({accesses}[^"]+)""",
    """ip_address:\s*"*({src_ip}[a-fA-F\d.:]+)""",
    """contact_id:\s*"*({contact_id}(-)?\d+)""",
    """source:\s*"*({download_source}[^"]+)""",
  ]
  DupFields = [ "accesses->activity" ]
}
```