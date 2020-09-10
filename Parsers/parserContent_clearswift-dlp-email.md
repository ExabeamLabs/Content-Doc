#### Parser Content
```Java
{
Name = clearswift-dlp-email
  Vendor = Clearswift SEG
  Product = Clearswift SEG
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """msgs IACPT|""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){3}({sender}[^\|]+)""",
    """([^\|]*\|){3}[^@]+@({external_domain_sender}[^@\|]+)""",
    """([^\|]*\|){4}({recipient}[^\|,]+)""",
    """([^\|]*\|){4}[^@]+@({external_domain_recipient}[^@\|,]+)""",
    """([^\|]*\|){4}({recipients}[^\|]+)""",
    """([^\|]*\|){5}({subject}[^\|]+)""",
    """([^\|]*\|){6}({outcome}[^\|]+)""",
    """([^\|]*\|){7}(|({attachment}[^.]+.({file_ext}[^,"|]+)[^\|]+))\|"""
  ]
}
```