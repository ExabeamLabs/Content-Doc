#### Parser Content
```Java
{
Name = siteminder-auth-attempt
    Vendor = SiteMinder
    Product = SiteMinder
    Lms = Splunk
    DataType = "authentication-attempt"
    TimeFormat = "MMM dd',' yyyy',' HH:mm:ss a"
    Conditions = [""""CA SiteMinder@""", """Authentication"""]
    Fields = [
      """"({auth_type}[^"]+?)","CA SiteMinder@"""
      """"CA SiteMinder@.*?",("[^"]+?",){1}"({time}\w+ \d+, \d\d\d\d, \d+:\d+:\d+ (AM|PM|am|pm))""""
      """"CA SiteMinder@.*?",("[^"]+?",){2}"({outcome}[^"]+?)""""
      """"CA SiteMinder@.*?",("[^"]+?",){3}"({src_ip}[A-Fa-f:\d.]+?)""""
      """"CA SiteMinder@.*?",("[^"]+?",){5}"({dest_ip}[A-Fa-f:\d.]+?)""""
      """"CA SiteMinder@.*?",("[^"]+?",){7}"({user}[^"]+?)""""
    ]
  } 

{
  Name = q-sendmail-dlp-email-alert
  Vendor = Sendmail
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[Web] Sent e-mail""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\]:\s*\(({src_ip}[a-fA-F:\d.]+).*?\[Web\] Sent e-mail""",
    """User:\s*({sender}[^\s\)]+)""",
    """User:\s*[^@]+@({external_domain_sender}[^\s\)]+)""",
    """Subject:\s*({subject}.+?);\s*To:""",
    """To:\s*({recipients}.+?)\s+with files:""",
    """To:\s*({recipient}[^\s,]+)""",
    """To:\s*[^@]+@({external_domain_recipient}[^@\s,]+)""",
    """files:\s*.*?[\\\/]*({file_name}[^\\\/]+?)\s*\(""",
    """files:\s*({attachments}.+?)\s*$""",
    """files:\s*.*?[\\\/]*({attachment}.+?)\s*\(({bytes_num}[\d\.]+)\s*({bytes_unit}[^\s\)]+)""",
  ]
}
```