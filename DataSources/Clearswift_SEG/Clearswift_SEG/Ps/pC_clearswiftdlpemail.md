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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^\|]{0,2000}\|){3}({sender}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){3}[^@]{1,2000}@({external_domain_sender}[^@\|]{1,2000})""",
    """([^\|]{0,2000}\|){4}({recipient}[^\|,]{1,2000})""",
    """([^\|]{0,2000}\|){4}[^@]{1,2000}@({external_domain_recipient}[^@\|,]{1,2000})""",
    """([^\|]{0,2000}\|){4}({recipients}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){5}({subject}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){6}({outcome}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){7}(|({attachment}[^.]{1,2000}.({file_ext}[^,"|]{1,2000})[^\|]{1,2000}))\|"""
  ]
}
```